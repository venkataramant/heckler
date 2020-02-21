package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.braintreeps.com/lollipopman/heckler/internal/gitutil"
	"github.braintreeps.com/lollipopman/heckler/internal/hecklerpb"
	"github.braintreeps.com/lollipopman/heckler/internal/puppetutil"
	"github.com/Masterminds/sprig"
	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/github"
	git "github.com/libgit2/git2go"
	gitcgiserver "github.com/lollipopman/git-cgi-server"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

const GitHubEnterpriseURL = "https://github.braintreeps.com/api/v3"

const (
	ApplicationName = "git-cgi-server"

	defaultAddr     = ":8080"
	shutdownTimeout = time.Second * 5
	port            = ":50051"
)

var Debug = false
var RegexDefineType = regexp.MustCompile(`^[A-Z][a-zA-Z0-9_:]*\[[^\]]+\]$`)

// hecklerServer is used to implement heckler.HecklerServer
type hecklerServer struct {
	hecklerpb.UnimplementedHecklerServer
	conf      *HecklerdConf
	repo      *git.Repository
	templates *template.Template
}

type Node struct {
	host                 string
	commitReports        map[git.Oid]*puppetutil.PuppetReport
	commitDeltaResources map[git.Oid]map[ResourceTitle]*deltaResource
	rizzoClient          puppetutil.RizzoClient
	lastApply            *git.Oid
}

type deltaResource struct {
	Title      ResourceTitle
	Type       string
	DefineType string
	Events     []*puppetutil.Event
	Logs       []*puppetutil.Log
}

type groupedResource struct {
	Title      ResourceTitle
	Type       string
	DefineType string
	Diff       string
	Nodes      []string
	Events     []*groupEvent
	Logs       []*groupLog
}

type groupEvent struct {
	PreviousValue string
	DesiredValue  string
}

type groupLog struct {
	Level   string
	Message string
}

type ResourceTitle string

func commitParentReports(commit *git.Commit, commitReports map[git.Oid]*puppetutil.PuppetReport) []*puppetutil.PuppetReport {
	var parentReports []*puppetutil.PuppetReport

	parentCount := commit.ParentCount()
	for i := uint(0); i < parentCount; i++ {
		parentReports = append(parentReports, commitReports[*commit.ParentId(i)])
	}
	return parentReports
}

func grpcConnect(node *Node, clientConnChan chan *Node) {
	address := node.host + ":50051"
	log.Printf("Dialing: %v", node.host)
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Unable to connect to: %v, %v", address, err)
	}
	log.Printf("Connected: %v", node.host)
	node.rizzoClient = puppetutil.NewRizzoClient(conn)
	clientConnChan <- node
}

func dialNodes(hosts []string) map[string]*Node {
	nodes := make(map[string]*Node)
	clientConnChan := make(chan *Node)
	for _, host := range hosts {
		nodes[host] = new(Node)
		nodes[host].host = host
	}

	for _, node := range nodes {
		go grpcConnect(node, clientConnChan)
	}

	var node *Node
	for range nodes {
		node = <-clientConnChan
		nodes[node.host] = node
	}
	return nodes
}

func commitLogIdList(repo *git.Repository, beginRev string, endRev string) ([]git.Oid, map[git.Oid]*git.Commit, error) {
	var commitLogIds []git.Oid
	var commits map[git.Oid]*git.Commit

	commits = make(map[git.Oid]*git.Commit)

	log.Printf("Walk begun: %s..%s\n", beginRev, endRev)
	rv, err := repo.Walk()
	if err != nil {
		return nil, nil, err
	}

	// We what to sort by the topology of the date of the commits. Also, reverse
	// the sort so the first commit in the array is the earliest commit or oldest
	// ancestor in the topology.
	rv.Sorting(git.SortTopological | git.SortReverse)

	// XXX only tags???
	err = rv.PushRef("refs/tags/" + endRev)
	if err != nil {
		return nil, nil, err
	}
	err = rv.HideRef("refs/tags/" + beginRev)
	if err != nil {
		return nil, nil, err
	}

	var c *git.Commit
	var gi git.Oid
	for rv.Next(&gi) == nil {
		commitLogIds = append(commitLogIds, gi)
		c, err = repo.LookupCommit(&gi)
		if err != nil {
			return nil, nil, err
		}
		commits[gi] = c
		log.Printf("commit: %s\n", gi.String())
	}
	log.Printf("Walk Complete\n")

	return commitLogIds, commits, nil
}

func noopCommitRange(nodes map[string]*Node, beginRev, endRev string, commitLogIds []git.Oid, commits map[git.Oid]*git.Commit, repo *git.Repository) (map[git.Oid][]*groupedResource, error) {
	var err error
	var data []byte
	puppetReportChan := make(chan puppetutil.PuppetReport)

	// Make dir structure
	// e.g. /var/heckler/v1..v2//oid.json

	// XXX /var or /var/lib?
	revdir := fmt.Sprintf("/var/heckler/%s..%s", beginRev, endRev)

	os.MkdirAll(revdir, 077)
	for host, _ := range nodes {
		os.Mkdir(revdir+"/"+host, 077)
	}

	var groupedCommits map[git.Oid][]*groupedResource

	groupedCommits = make(map[git.Oid][]*groupedResource)

	for _, node := range nodes {
		node.commitReports = make(map[git.Oid]*puppetutil.PuppetReport)
		node.commitDeltaResources = make(map[git.Oid]map[ResourceTitle]*deltaResource)
	}

	var noopRequests int
	var reportPath string
	var file *os.File
	var rprt *puppetutil.PuppetReport

	for i, commitLogId := range commitLogIds {
		log.Printf("Nooping: %s (%d of %d)", commitLogId.String(), i, len(commitLogIds))
		par := puppetutil.PuppetApplyRequest{Rev: commitLogId.String(), Noop: true}
		noopRequests = 0
		for host, node := range nodes {
			if node.lastApply == nil {
				log.Fatalf("Node, %s, does not have a lastApply commit id", node.host)
			}
			reportPath = revdir + "/" + host + "/" + commitLogId.String() + ".json"
			if commitAlreadyApplied(node.lastApply, &commitLogId, repo) {
				// Use empty report if commit already applied, i.e. empty puppet noop diff
				log.Printf("Already applied using empty noop: %s@%s", node.host, commitLogId.String())
				nodes[node.host].commitReports[commitLogId] = new(puppetutil.PuppetReport)
			} else {
				if _, err := os.Stat(reportPath); err == nil {
					file, err = os.Open(reportPath)
					if err != nil {
						log.Fatal(err)
					}
					defer file.Close()

					data, err = ioutil.ReadAll(file)
					if err != nil {
						log.Fatalf("cannot read report: %v", err)
					}
					rprt = new(puppetutil.PuppetReport)
					err = json.Unmarshal([]byte(data), rprt)
					if err != nil {
						log.Fatalf("cannot unmarshal report: %v", err)
					}
					if host != rprt.Host {
						log.Fatalf("Host mismatch %s != %s", host, rprt.Host)
					}
					log.Printf("Found serialized noop: %s@%s", rprt.Host, rprt.ConfigurationVersion)
					nodes[rprt.Host].commitReports[commitLogId] = rprt
				} else {
					go hecklerApply(node.rizzoClient, puppetReportChan, par)
					noopRequests++
				}
			}
		}

		for j := 0; j < noopRequests; j++ {
			rprt := <-puppetReportChan
			log.Printf("Received noop: %s@%s", rprt.Host, rprt.ConfigurationVersion)
			nodes[rprt.Host].commitReports[commitLogId] = &rprt
			nodes[rprt.Host].commitReports[commitLogId].Logs = normalizeLogs(nodes[rprt.Host].commitReports[commitLogId].Logs)

			reportPath = revdir + "/" + rprt.Host + "/" + commitLogId.String() + ".json"
			data, err = json.Marshal(rprt)
			if err != nil {
				log.Fatalf("Cannot marshal report: %v", err)
			}
			err = ioutil.WriteFile(reportPath, data, 0644)
			if err != nil {
				log.Fatalf("Cannot write report: %v", err)
			}

		}
	}

	for host, node := range nodes {
		for i, gi := range commitLogIds {
			if i == 0 {
				node.commitDeltaResources[gi] = deltaNoop(node.commitReports[gi], []*puppetutil.PuppetReport{new(puppetutil.PuppetReport)})
			} else {
				log.Printf("Creating delta resource: %s@%s", host, gi.String())
				node.commitDeltaResources[gi] = deltaNoop(node.commitReports[gi], commitParentReports(commits[gi], node.commitReports))
			}
		}
	}

	for _, gi := range commitLogIds {
		log.Printf("Grouping: %s", gi.String())
		for _, node := range nodes {
			for _, nodeDeltaRes := range node.commitDeltaResources[gi] {
				groupedCommits[gi] = append(groupedCommits[gi], groupResources(gi, nodeDeltaRes, nodes))
			}
		}
	}
	return groupedCommits, nil
}

func priorEvent(event *puppetutil.Event, resourceTitleStr string, priorCommitNoops []*puppetutil.PuppetReport) bool {
	for _, priorCommitNoop := range priorCommitNoops {
		if priorResourceStatuses, ok := priorCommitNoop.ResourceStatuses[resourceTitleStr]; ok {
			for _, priorEvent := range priorResourceStatuses.Events {
				if *event == *priorEvent {
					return true
				}
			}
		}
	}
	return false
}

func priorLog(log *puppetutil.Log, priorCommitNoops []*puppetutil.PuppetReport) bool {
	for _, priorCommitNoop := range priorCommitNoops {
		for _, priorLog := range priorCommitNoop.Logs {
			if *log == *priorLog {
				return true
			}
		}
	}
	return false
}

func initDeltaResource(resourceTitle ResourceTitle, r *puppetutil.ResourceStatus, deltaEvents []*puppetutil.Event, deltaLogs []*puppetutil.Log) *deltaResource {
	deltaRes := new(deltaResource)
	deltaRes.Title = resourceTitle
	deltaRes.Type = r.ResourceType
	deltaRes.Events = deltaEvents
	deltaRes.Logs = deltaLogs
	deltaRes.DefineType = resourceDefineType(r)
	return deltaRes
}

func deltaNoop(commitNoop *puppetutil.PuppetReport, priorCommitNoops []*puppetutil.PuppetReport) map[ResourceTitle]*deltaResource {
	var deltaEvents []*puppetutil.Event
	var deltaLogs []*puppetutil.Log
	var deltaResources map[ResourceTitle]*deltaResource
	var resourceTitle ResourceTitle

	deltaResources = make(map[ResourceTitle]*deltaResource)

	if commitNoop.ResourceStatuses == nil {
		return deltaResources
	}

	for resourceTitleStr, r := range commitNoop.ResourceStatuses {
		deltaEvents = nil
		deltaLogs = nil

		for _, event := range r.Events {
			if priorEvent(event, resourceTitleStr, priorCommitNoops) == false {
				deltaEvents = append(deltaEvents, event)
			}
		}

		for _, log := range commitNoop.Logs {
			if log.Source == resourceTitleStr {
				if priorLog(log, priorCommitNoops) == false {
					deltaLogs = append(deltaLogs, log)
				}
			}
		}

		if len(deltaEvents) > 0 || len(deltaLogs) > 0 {
			resourceTitle = ResourceTitle(resourceTitleStr)
			deltaResources[resourceTitle] = initDeltaResource(resourceTitle, r, deltaEvents, deltaLogs)
		}
	}

	return deltaResources
}

// Determine if a commit is already applied based on the last appliedCommit.
// If the potentialCommit is an ancestor of the appliedCommit then we know the
// potentialCommit has already been applied.
func commitAlreadyApplied(appliedCommit *git.Oid, potentialCommit *git.Oid, repo *git.Repository) bool {
	if appliedCommit.Equal(potentialCommit) {
		return true
	}
	descendant, err := repo.DescendantOf(appliedCommit, potentialCommit)
	if err != nil {
		log.Fatalf("Cannot determine descendant status: %v", err)
	}
	return descendant
}

func normalizeDiff(msg string) string {
	var newMsg string
	var s string
	var line int

	scanner := bufio.NewScanner(strings.NewReader(msg))
	line = 0
	for scanner.Scan() {
		s = scanner.Text()
		if line > 2 {
			newMsg += s + "\n"
		}
		line++
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return newMsg
}

func resourceDefineType(res *puppetutil.ResourceStatus) string {
	var defineType string

	cplen := len(res.ContainmentPath)
	if cplen > 2 {
		possibleDefineType := res.ContainmentPath[cplen-2]
		if RegexDefineType.MatchString(possibleDefineType) {
			defineType = possibleDefineType
		}
	}
	return defineType
}

func groupResources(commitLogId git.Oid, targetDeltaResource *deltaResource, nodes map[string]*Node) *groupedResource {
	var nodeList []string
	var desiredValue string
	// XXX Remove this hack, only needed for old versions of puppet 4.5?
	var regexRubySym = regexp.MustCompile(`^:`)
	var gr *groupedResource
	var ge *groupEvent
	var gl *groupLog

	for nodeName, node := range nodes {
		if nodeDeltaResource, ok := node.commitDeltaResources[commitLogId][targetDeltaResource.Title]; ok {
			if cmp.Equal(targetDeltaResource, nodeDeltaResource) {
				nodeList = append(nodeList, nodeName)
				delete(node.commitDeltaResources[commitLogId], targetDeltaResource.Title)
			}
		}
	}

	gr = new(groupedResource)
	gr.Title = targetDeltaResource.Title
	gr.Type = targetDeltaResource.Type
	gr.DefineType = targetDeltaResource.DefineType
	sort.Strings(nodeList)
	gr.Nodes = nodeList

	for _, e := range targetDeltaResource.Events {
		ge = new(groupEvent)

		ge.PreviousValue = regexRubySym.ReplaceAllString(e.PreviousValue, "")
		// XXX move base64 decode somewhere else
		// also yell at puppet for this inconsistency!!!
		if targetDeltaResource.Type == "File" && e.Property == "content" {
			data, err := base64.StdEncoding.DecodeString(e.DesiredValue)
			if err != nil {
				// XXX nasty, fix?
				desiredValue = e.DesiredValue
			} else {
				desiredValue = string(data[:])
			}
		} else {
			desiredValue = regexRubySym.ReplaceAllString(e.DesiredValue, "")
		}
		ge.DesiredValue = desiredValue
		gr.Events = append(gr.Events, ge)
	}
	regexDiff := regexp.MustCompile(`^@@ `)
	for _, l := range targetDeltaResource.Logs {
		if regexDiff.MatchString(l.Message) {
			gr.Diff = strings.TrimSuffix(l.Message, "\n")
		} else {

			gl = new(groupLog)
			gl.Level = l.Level
			gl.Message = strings.TrimRight(l.Message, "\n")
			gr.Logs = append(gr.Logs, gl)
		}
	}
	return gr
}

func normalizeLogs(Logs []*puppetutil.Log) []*puppetutil.Log {
	var newSource string
	var origSource string
	var newLogs []*puppetutil.Log

	// extract resource from log source
	regexResourcePropertyTail := regexp.MustCompile(`/[a-z][a-z0-9_]*$`)
	regexResourceTail := regexp.MustCompile(`[^\/]+\[[^\[\]]+\]$`)

	// normalize diff
	reFileContent := regexp.MustCompile(`File\[.*content$`)
	reDiff := regexp.MustCompile(`(?s)^.---`)

	// Log referring to a puppet resource
	regexResource := regexp.MustCompile(`^/Stage`)

	// Log msg values to drop
	regexCurValMsg := regexp.MustCompile(`^current_value`)
	regexApplyMsg := regexp.MustCompile(`^Applied catalog`)
	regexRefreshMsg := regexp.MustCompile(`^Would have triggered 'refresh'`)

	// Log sources to drop
	regexClass := regexp.MustCompile(`^Class\[`)
	regexStage := regexp.MustCompile(`^Stage\[`)

	for _, l := range Logs {
		origSource = ""
		newSource = ""
		if regexCurValMsg.MatchString(l.Message) ||
			regexApplyMsg.MatchString(l.Message) {
			if Debug {
				fmt.Fprintf(os.Stderr, "Dropping Log: %v: %v\n", l.Source, l.Message)
			}
			continue
		} else if regexClass.MatchString(l.Source) ||
			regexStage.MatchString(l.Source) ||
			RegexDefineType.MatchString(l.Source) {
			if Debug {
				fmt.Fprintf(os.Stderr, "Dropping Log: %v: %v\n", l.Source, l.Message)
			}
			continue
		} else if (!regexResource.MatchString(l.Source)) && regexRefreshMsg.MatchString(l.Message) {
			if Debug {
				fmt.Fprintf(os.Stderr, "Dropping Log: %v: %v\n", l.Source, l.Message)
			}
			continue
		} else if regexResource.MatchString(l.Source) {
			origSource = l.Source
			newSource = regexResourcePropertyTail.ReplaceAllString(l.Source, "")
			newSource = regexResourceTail.FindString(newSource)
			if newSource == "" {
				fmt.Fprintf(os.Stderr, "newSource is empty!\n")
				fmt.Fprintf(os.Stderr, "Log: '%v' -> '%v': %v\n", origSource, newSource, l.Message)
				os.Exit(1)
			}

			if reFileContent.MatchString(l.Source) && reDiff.MatchString(l.Message) {
				l.Message = normalizeDiff(l.Message)
			}
			l.Source = newSource
			if Debug {
				fmt.Fprintf(os.Stderr, "Adding Log: '%v' -> '%v': %v\n", origSource, newSource, l.Message)
			}
			newLogs = append(newLogs, l)
		} else {
			fmt.Fprintf(os.Stderr, "Unaccounted for Log: %v: %v\n", l.Source, l.Message)
			newLogs = append(newLogs, l)
		}
	}

	return newLogs
}

func hecklerApply(rc puppetutil.RizzoClient, c chan<- puppetutil.PuppetReport, par puppetutil.PuppetApplyRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	r, err := rc.PuppetApply(ctx, &par)
	if err != nil {
		c <- puppetutil.PuppetReport{}
	}
	if ctx.Err() != nil {
		log.Printf("ERROR: Context error: %v", ctx.Err())
		c <- puppetutil.PuppetReport{}
	}
	c <- *r
}

func parseTemplates() *template.Template {
	var templatesPath string
	if _, err := os.Stat("/usr/share/heckler/templates"); err == nil {
		templatesPath = "/usr/share/heckler/templates" + "/*.tmpl"
	} else {
		templatesPath = "*.tmpl"
	}
	return template.Must(template.New("base").Funcs(sprig.TxtFuncMap()).ParseGlob(templatesPath))
}

func (hs *hecklerServer) HecklerApply(ctx context.Context, req *hecklerpb.HecklerApplyRequest) (*hecklerpb.HecklerApplyReport, error) {
	nodes := dialNodes(req.Nodes)
	par := puppetutil.PuppetApplyRequest{Rev: req.Rev, Noop: req.Noop}
	puppetReportChan := make(chan puppetutil.PuppetReport)
	for _, node := range nodes {
		go hecklerApply(node.rizzoClient, puppetReportChan, par)
	}

	for range nodes {
		r := <-puppetReportChan
		if cmp.Equal(r, puppetutil.PuppetReport{}) {
			log.Fatalf("Received an empty report")
		} else if r.Status == "failed" {
			log.Printf("ERROR: Apply failed, %s@%s", r.Host, r.ConfigurationVersion)
		} else {
			if req.Noop {
				log.Printf("Nooped: %s@%s", r.Host, r.ConfigurationVersion)
			} else {
				log.Printf("Applied: %s@%s", r.Host, r.ConfigurationVersion)
			}
		}
	}
	har := new(hecklerpb.HecklerApplyReport)
	return har, nil
}

func (hs *hecklerServer) HecklerNoopRange(ctx context.Context, req *hecklerpb.HecklerNoopRangeRequest) (*hecklerpb.HecklerNoopRangeReport, error) {
	nodes := dialNodes(req.Nodes)
	err := nodeLastApply(nodes, hs.repo)
	if err != nil {
		return nil, err
	}
	commitLogIds, commits, err := commitLogIdList(hs.repo, req.BeginRev, req.EndRev)
	if err != nil {
		return nil, err
	}
	groupedCommits, err := noopCommitRange(nodes, req.BeginRev, req.EndRev, commitLogIds, commits, hs.repo)
	if err != nil {
		return nil, err
	}
	if req.GithubMilestone != "" {
		githubCreate(req.GithubMilestone, commitLogIds, groupedCommits, commits, hs.templates)
	}
	hnrr := new(hecklerpb.HecklerNoopRangeReport)
	if req.OutputFormat == hecklerpb.OutputFormat_markdown {
		hnrr.Output = markdownOutput(commitLogIds, commits, groupedCommits, hs.templates)
	}
	return hnrr, nil
}

func githubCreate(githubMilestone string, commitLogIds []git.Oid, groupedCommits map[git.Oid][]*groupedResource, commits map[git.Oid]*git.Commit, templates *template.Template) {
	// Shared transport to reuse TCP connections.
	tr := http.DefaultTransport

	var privateKeyPath string
	if _, err := os.Stat("/etc/heckler/github-private-key.pem"); err == nil {
		privateKeyPath = "/etc/heckler/github-private-key.pem"
	} else if _, err := os.Stat("github-private-key.pem"); err == nil {
		privateKeyPath = "github-private-key.pem"
	} else {
		log.Fatal("Unable to load github-private-key.pem in /etc/heckler or .")
	}
	// Wrap the shared transport for use with the app ID 7 authenticating with
	// installation ID 11.
	itr, err := ghinstallation.NewKeyFromFile(tr, 7, 11, privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	itr.BaseURL = GitHubEnterpriseURL

	// Use installation transport with github.com/google/go-github
	client, err := github.NewEnterpriseClient(GitHubEnterpriseURL, GitHubEnterpriseURL, &http.Client{Transport: itr})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	m := &github.Milestone{
		Title: github.String(githubMilestone),
	}
	nm, _, err := client.Issues.CreateMilestone(ctx, "lollipopman", "muppetshow", m)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Successfully created new milestone: %v\n", *nm.Title)

	for _, gi := range commitLogIds {
		if len(groupedCommits[gi]) == 0 {
			log.Printf("Skipping %s, no noop output\n", gi.String())
			continue
		}
		githubIssue := &github.IssueRequest{
			Title:     github.String(fmt.Sprintf("Puppet noop output for commit: '%v'", commits[gi].Summary())),
			Assignee:  github.String(commits[gi].Author().Name),
			Body:      github.String(commitToMarkdown(commits[gi], templates) + groupedResourcesToMarkdown(groupedCommits[gi], templates)),
			Milestone: nm.Number,
		}
		ni, _, err := client.Issues.Create(ctx, "lollipopman", "muppetshow", githubIssue)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Successfully created new issue: %v\n", *ni.Title)
	}
}

func markdownOutput(commitLogIds []git.Oid, commits map[git.Oid]*git.Commit, groupedCommits map[git.Oid][]*groupedResource, templates *template.Template) string {
	var output string
	for _, gi := range commitLogIds {
		if len(groupedCommits[gi]) == 0 {
			log.Printf("Skipping %s, no noop output\n", gi.String())
			continue
		}
		output += fmt.Sprintf("## Puppet noop output for commit: '%v'\n\n", commits[gi].Summary())
		output += commitToMarkdown(commits[gi], templates)
		output += groupedResourcesToMarkdown(groupedCommits[gi], templates)
	}
	return output
}

func commitToMarkdown(c *git.Commit, templates *template.Template) string {
	var body strings.Builder
	var err error

	err = templates.ExecuteTemplate(&body, "commit.tmpl", c)
	if err != nil {
		log.Fatal(err)
	}
	return body.String()
}

func groupedResourcesToMarkdown(groupedResources []*groupedResource, templates *template.Template) string {
	var body strings.Builder
	var err error

	sort.Slice(
		groupedResources,
		func(i, j int) bool {
			if string(groupedResources[i].Title) == string(groupedResources[j].Title) {
				// if the resources titles are equal sort by the list of nodes affected
				return strings.Join(groupedResources[i].Nodes[:], ",") < strings.Join(groupedResources[j].Nodes[:], ",")
			} else {
				return string(groupedResources[i].Title) < string(groupedResources[j].Title)
			}
		})

	err = templates.ExecuteTemplate(&body, "groupedResource.tmpl", groupedResources)
	if err != nil {
		log.Fatal(err)
	}
	return body.String()
}

func (hs *hecklerServer) HecklerStatus(ctx context.Context, req *hecklerpb.HecklerStatusRequest) (*hecklerpb.HecklerStatusReport, error) {
	nodes := dialNodes(req.Nodes)
	err := nodeLastApply(nodes, hs.repo)
	if err != nil {
		return nil, err
	}
	hsr := new(hecklerpb.HecklerStatusReport)
	hsr.NodeStatuses = make(map[string]string)
	for _, node := range nodes {
		hsr.NodeStatuses[node.host] = node.lastApply.String()
	}
	return hsr, nil
}

func hecklerLastApply(rc puppetutil.RizzoClient, c chan<- puppetutil.PuppetReport) {
	plar := puppetutil.PuppetLastApplyRequest{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	r, err := rc.PuppetLastApply(ctx, &plar)
	if err != nil {
		c <- puppetutil.PuppetReport{}
	}
	c <- *r
}

func nodeLastApply(nodes map[string]*Node, repo *git.Repository) error {
	var err error

	puppetReportChan := make(chan puppetutil.PuppetReport)
	for _, node := range nodes {
		go hecklerLastApply(node.rizzoClient, puppetReportChan)
	}

	var obj *git.Object
	for range nodes {
		r := <-puppetReportChan
		obj, err = repo.RevparseSingle(r.ConfigurationVersion)
		if err != nil {
			return err
		}
		if node, ok := nodes[r.Host]; ok {
			node.lastApply = obj.Id()
		} else {
			log.Fatalf("No Node struct found for report from: %s\n", r.Host)
		}
	}

	return nil
}

func fetchRepo(conf *HecklerdConf) (*git.Repository, error) {

	// Shared transport to reuse TCP connections.
	tr := http.DefaultTransport

	// XXX dedup with heckler
	var privateKeyPath string
	if _, err := os.Stat("/etc/heckler/github-private-key.pem"); err == nil {
		privateKeyPath = "/etc/heckler/github-private-key.pem"
	} else if _, err := os.Stat("github-private-key.pem"); err == nil {
		privateKeyPath = "github-private-key.pem"
	} else {
		log.Fatal("Unable to load github-private-key.pem in /etc/heckler or .")
	}
	// Wrap the shared transport for use with the app ID 7 authenticating with
	// installation ID 11.
	itr, err := ghinstallation.NewKeyFromFile(tr, 7, 11, privateKeyPath)
	if err != nil {
		return nil, err
	}
	itr.BaseURL = GitHubEnterpriseURL

	// Use installation transport with github.com/google/go-github
	_, err = github.NewEnterpriseClient(GitHubEnterpriseURL, GitHubEnterpriseURL, &http.Client{Transport: itr})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	tok, err := itr.Token(ctx)
	if err != nil {
		return nil, err
	}

	cloneDir := "/var/lib/hecklerd/served_repo/puppetcode"
	cloneOptions := &git.CloneOptions{}
	cloneOptions.Bare = true
	remoteUrl := fmt.Sprintf("https://x-access-token:%s@"+conf.PuppetCodeGitURL, tok)
	bareRepo, err := gitutil.CloneOrOpen(remoteUrl, cloneDir, cloneOptions)
	if err != nil {
		return nil, err
	}
	err = gitutil.FastForward(bareRepo, nil)
	if err != nil {
		return nil, err
	}
	return bareRepo, nil
}

type HecklerdConf struct {
	PuppetCodeGitURL string `yaml:"puppet_code_git_url"`
}

func main() {
	var err error
	var hecklerdConfPath string
	var hecklerdConf *HecklerdConf
	var file *os.File
	var data []byte
	templates := parseTemplates()

	if _, err := os.Stat("/etc/heckler/hecklerd_conf.yaml"); err == nil {
		hecklerdConfPath = "/etc/heckler/hecklerd_conf.yaml"
	} else if _, err := os.Stat("hecklerd_conf.yaml"); err == nil {
		hecklerdConfPath = "hecklerd_conf.yaml"
	} else {
		log.Fatal("Unable to load hecklerd_conf.yaml from /etc/heckler or .")
	}
	file, err = os.Open(hecklerdConfPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	data, err = ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Cannot read config: %v", err)
	}
	hecklerdConf = new(HecklerdConf)
	err = yaml.Unmarshal([]byte(data), hecklerdConf)
	if err != nil {
		log.Fatalf("Cannot unmarshal config: %v", err)
	}

	repo, err := fetchRepo(hecklerdConf)
	if err != nil {
		log.Fatalf("Unable to fetch repo to serve: %v", err)
	}

	gitServer := &gitcgiserver.GitCGIServer{}
	gitServer.ExportAll = true
	gitServer.ProjectRoot = "/var/lib/hecklerd/served_repo"
	gitServer.Addr = defaultAddr
	gitServer.ShutdownTimeout = shutdownTimeout

	idleConnsClosed := make(chan struct{})
	done := make(chan bool, 1)

	// background polling git fetch
	go func() {
		for {
			time.Sleep(5 * time.Second)
			_, err = fetchRepo(hecklerdConf)
			if err != nil {
				log.Fatalf("Unable to fetch repo: %v", err)
			}
		}
	}()

	// git server
	go func() {
		log.Printf("Starting Git HTTP server on %s (PID=%d)\n", gitServer.Addr, os.Getpid())
		if err := gitServer.Serve(); err != nil && err != http.ErrServerClosed {
			log.Println("Git HTTP server error:", err)
		}
		<-idleConnsClosed
	}()

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	hecklerServer := new(hecklerServer)
	hecklerServer.conf = hecklerdConf
	hecklerServer.templates = templates
	hecklerServer.repo = repo
	hecklerpb.RegisterHecklerServer(grpcServer, hecklerServer)

	// grpc server
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// XXX any reason to make this a separate goroutine?
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		log.Printf("Received %s\n", <-sigs)
		if err := gitServer.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
		close(idleConnsClosed)
		grpcServer.GracefulStop()
		log.Println("Heckler Shutdown")
		done <- true
	}()

	<-done
}
