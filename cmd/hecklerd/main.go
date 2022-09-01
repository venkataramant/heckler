package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/Masterminds/sprig"
	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-github/v29/github"
	"github.com/hmarr/codeowners"
	git "github.com/libgit2/git2go/v31"
	gitcgiserver "github.com/lollipopman/git-cgi-server"
	"github.com/braintree/heckler/internal/gitutil"
	"github.com/braintree/heckler/internal/heckler"
	"github.com/braintree/heckler/internal/hecklerpb"
	"github.com/braintree/heckler/internal/puppetutil"
	"github.com/braintree/heckler/internal/rizzopb"
	"github.com/rickar/cal/v2"
	"github.com/rickar/cal/v2/us"
	"github.com/robfig/cron/v3"
	"github.com/slack-go/slack"
	"github.com/square/grange"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

var Version string
var ErrLastApplyUnknown = errors.New("Unable to determine lastApply commit, use force flag to update")
var ErrThresholdExceeded = errors.New("Threshold for err nodes or lock nodes exceeded")

type applyError struct {
	Host   string
	Report rizzopb.PuppetReport
}

func (e *applyError) Error() string {
	return fmt.Sprintf("Apply status: '%s', %s", e.Report.Status, e.Report.ConfigurationVersion)
}

type cleanError struct {
	Host      string
	LastApply git.Oid
	Report    rizzopb.PuppetReport
}

func (e *cleanError) Error() string {
	return fmt.Sprintf("Unable to clean %s, no diffless noops found near its last apply of '%s-dirty'", e.Host, e.LastApply.String())
}

type noopInvalidError struct {
	Host          string
	LastApply     git.Oid
	NoopLastApply git.Oid
}

func (e *noopInvalidError) Error() string {
	return fmt.Sprintf("Noop is invalid, %s last apply is '%s', but noop is against '%s'", e.Host, e.LastApply.String(), e.NoopLastApply.String())
}

type resourceApproverType string

const (
	resourceNotApproved        resourceApproverType = "Not Approved"
	resourceSourceFileApproved                      = "Source File Approved"
	resourceModuleApproved                          = "Module Approved"
	resourceNodesApproved                           = "Nodes Approved"
)

type noopApproverType int

const (
	notApproved noopApproverType = iota
	codeownersApproved
	adminApproved
)

func (noopApproved noopApproverType) String() string {
	var msg string
	switch noopApproved {
	case notApproved:
		msg = "Unapproved"
	case codeownersApproved:
		msg = "Owner Approved"
	case adminApproved:
		msg = "Admin Approved"
	}
	return msg
}

type noopStatus struct {
	approved     noopApproverType
	approvers    []string
	authors      []string
	ownersNeeded []string
}

type lastApplyStatus int

const (
	lastApplyClean lastApplyStatus = iota
	lastApplyDirty
	lastApplyErrored
)

const (
	ApplicationName = "git-cgi-server"
	shutdownTimeout = time.Second * 5
	// HACK: Bind to ipv4
	// TODO: move to HecklerdConf
	defaultAddr = "0.0.0.0:8080"
	port        = ":50052"
)

var Debug = false

// TODO: this regex also matches, Node[__node_regexp__fozzie], which causes
// resources in node blocks to be mistaken for define types. Is there a more
// robust way to match for define types?
var RegexDefineType = regexp.MustCompile(`^[A-Z][a-zA-Z0-9_:]*\[[^\]]+\]$`)
var RegexGithubGroup = regexp.MustCompile(`^@.*/.*$`)
var regexPuppetResourceCapture = regexp.MustCompile(`^([^\[].*)\[(.*)\]$`)

// SerializedRegexp embeds a regexp.Regexp, and adds Text/JSON
// (un)marshaling, https://stackoverflow.com/a/62558450
type SerializedRegexp struct {
	regexp.Regexp
}

// Compile wraps the result of the standard library's
// regexp.Compile, for easy (un)marshaling.
func SerializedRegexpCompile(expr string) (*SerializedRegexp, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return &SerializedRegexp{*re}, nil
}

// UnmarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Unmarshal.
func (r *SerializedRegexp) UnmarshalText(text []byte) error {
	rr, err := SerializedRegexpCompile(string(text))
	if err != nil {
		return err
	}
	*r = *rr
	return nil
}

// MarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Marshal.
func (r *SerializedRegexp) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

type Resource struct {
	Type       string            `yaml:"type"`
	Title      string            `yaml:"title,omitempty"`
	TitleRegex *SerializedRegexp `yaml:"title_regex,omitempty"`
}

type IgnoredResources struct {
	Purpose   string     `yaml:"purpose"`
	Rationale string     `yaml:"rationale"`
	Resources []Resource `yaml:"resources"`
}

type HecklerdConf struct {
	AdminOwners                []string              `yaml:"admin_owners"`
	ApplySetOrder              []string              `yaml:"apply_set_order"`
	ApplySetSleepSeconds       int                   `yaml:"apply_set_sleep_seconds"`
	AutoCloseIssues            bool                  `yaml:"auto_close_issues"`
	AutoTagCronSchedule        string                `yaml:"auto_tag_cron_schedule"`
	EnvPrefix                  string                `yaml:"env_prefix"`
	GitHubAppEmail             string                `yaml:"github_app_email"`
	GitHubAppId                int64                 `yaml:"github_app_id"`
	GitHubAppInstallId         int64                 `yaml:"github_app_install_id"`
	GitHubAppSlug              string                `yaml:"github_app_slug"`
	GitHubDisableNotifications bool                  `yaml:"github_disable_notifications"`
	GitHubDomain               string                `yaml:"github_domain"`
	GitHubHttpProxy            string                `yaml:"github_http_proxy"`
	GitHubPrivateKeyPath       string                `yaml:"github_private_key_path"`
	GitServerMaxClients        int                   `yaml:"git_server_max_clients"`
	GroupedNoopDir             string                `yaml:"grouped_noop_dir"`
	IgnoredResources           []IgnoredResources    `yaml:"ignored_resources"`
	LockMessage                string                `yaml:"lock_message"`
	LoopApprovalSleepSeconds   int                   `yaml:"loop_approval_sleep_seconds"`
	LoopCleanSleepSeconds      int                   `yaml:"loop_clean_sleep_seconds"`
	LoopMilestoneSleepSeconds  int                   `yaml:"loop_milestone_sleep_seconds"`
	LoopNoopSleepSeconds       int                   `yaml:"loop_noop_sleep_seconds"`
	ManualMode                 bool                  `yaml:"manual_mode"`
	MaxNodeThresholds          NodeThresholds        `yaml:"max_node_thresholds"`
	ModulesPaths               []string              `yaml:"module_paths"`
	NodeSets                   map[string]NodeSetCfg `yaml:"node_sets"`
	Timezone                   string                `yaml:"timezone"`
	HoundWait                  string                `yaml:"hound_wait"`
	HoundCronSchedule          string                `yaml:"hound_cron_schedule"`
	ApplyCronSchedule          string                `yaml:"apply_cron_schedule"`
	NoopDir                    string                `yaml:"noop_dir"`
	Repo                       string                `yaml:"repo"`
	RepoBranch                 string                `yaml:"repo_branch"`
	RepoOwner                  string                `yaml:"repo_owner"`
	ServedRepo                 string                `yaml:"served_repo"`
	SlackAnnounceChannels      []SlackChannelCfg     `yaml:"slack_announce_channels"`
	SlackPrivateConfPath       string                `yaml:"slack_private_conf_path"`
	StateDir                   string                `yaml:"state_dir"`
	WorkRepo                   string                `yaml:"work_repo"`
}

type SlackConf struct {
	Token string `yaml:"token"`
}

type NodeSetCfg struct {
	Cmd       []string `yaml:"cmd"`
	Blacklist []string `yaml:"blacklist"`
}

type SlackChannelCfg struct {
	Id   string `yaml:"id"`
	Name string `yaml:"name"`
}

type NodeSet struct {
	name           string
	commonTag      string
	nodeThresholds NodeThresholds
	nodes          Nodes
}

type Module struct {
	Name string
	Path string
}

type Nodes struct {
	active          map[string]*Node
	dialed          map[string]*Node
	errored         map[string]*Node
	locked          map[string]*Node
	lockedByAnother map[string]*Node
}

type NodeThresholds struct {
	Errored         int `yaml:"errored"`
	LockedByAnother int `yaml:"locked_by_another"`
}

// hecklerServer is used to implement heckler.HecklerServer
type hecklerServer struct {
	hecklerpb.UnimplementedHecklerServer
	conf      *HecklerdConf
	repo      *git.Repository
	templates *template.Template
}

type Node struct {
	host                 string
	commitReports        map[git.Oid]*rizzopb.PuppetReport
	commitDeltaResources map[git.Oid]map[ResourceTitle]*deltaResource
	rizzoClient          rizzopb.RizzoClient
	grpcConn             *grpc.ClientConn
	lastApply            git.Oid
	err                  error
	lockState            heckler.LockState
}

type applyResult struct {
	host   string
	report rizzopb.PuppetReport
	err    error
}

type dirtyNoops struct {
	rev       git.Oid
	dirtyNoop rizzopb.PuppetReport
	commitIds map[git.Oid]bool
}

type cleanNodeResult struct {
	host  string
	clean bool
	dn    dirtyNoops
	err   error
}

type deltaResource struct {
	Title           ResourceTitle
	Type            string
	DefineType      string
	File            string
	Line            int64
	ContainmentPath []string
	Events          []*rizzopb.Event
	Logs            []*rizzopb.Log
}

type groupedReport struct {
	GithubIssueId              int64
	CommitNotInAllNodeLineages bool
	Resources                  []*groupedResource
	Errors                     []*groupedError
	BeyondRev                  []*groupedBeyondRev
	LockedByAnother            []*groupedLockState
}

type groupedHosts []string

func (gh groupedHosts) String() string {
	return fmt.Sprintf("%s", compressHosts(gh))
}

type groupedError struct {
	Type  string
	Hosts groupedHosts
	Error string
}

func (ge groupedError) String() string {
	msg := fmt.Sprintf("Hosts: %v, Error: %s", ge.Hosts, ge.Type)
	if ge.Error != "" {
		msg += fmt.Sprintf(" - '%s'", ge.Error)
	}
	return msg
}

type groupedBeyondRev struct {
	LastApply git.Oid
	Hosts     groupedHosts
}

type groupedLockState struct {
	LockState heckler.LockState
	Hosts     groupedHosts
}

func (gls groupedLockState) String() string {
	return fmt.Sprintf("Hosts: %v, %v", gls.Hosts, gls.LockState)
}

type groupedResource struct {
	Title           ResourceTitle
	Type            string
	DefineType      string
	Diff            string
	File            string
	Line            int64
	Module          Module
	ContainmentPath []string
	Hosts           groupedHosts
	NodeFiles       []string
	Events          []*groupEvent
	Logs            []*groupLog
	Owners          groupedResourceOwners
	Approved        resourceApproverType
	Approvals       groupedResourceApprovals
	AdminApprovals  []string
}

type groupedResourceOwners struct {
	File      []string
	Module    []string
	NodeFiles map[string][]string
}

type groupedResourceApprovals struct {
	File      []string
	Module    []string
	NodeFiles map[string][]string
}

type noopOwners struct {
	OwnedModules       map[Module][]string
	OwnedNodeFiles     map[string][]string
	OwnedSourceFiles   map[string][]string
	UnownedModules     []Module
	UnownedNodeFiles   []string
	UnownedSourceFiles []string
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

func commitParentReports(commit git.Commit, lastApply git.Oid, commitReports map[git.Oid]*rizzopb.PuppetReport, host string, repo *git.Repository, logger *log.Logger) (bool, []*rizzopb.PuppetReport) {
	var parentReport *rizzopb.PuppetReport
	parentReports := make([]*rizzopb.PuppetReport, 0)
	parentCount := commit.ParentCount()
	parentEvalErrors := false
	for i := uint(0); i < parentCount; i++ {
		parentReport = commitReports[*commit.ParentId(i)]
		if parentReport == nil {
			logger.Fatalf("Parent report not found %s for commit %s@%s", commit.ParentId(i).String(), host, commit.Id().String())
		} else {
			parentReports = append(parentReports, parentReport)
			if parentReport.Status == "failed" {
				parentEvalErrors = true
			}
		}
	}
	return parentEvalErrors, parentReports
}

func grpcConnect(ctx context.Context, node *Node, clientConnChan chan *Node) {
	address := node.host + ":50051"
	ctx, cancel := context.WithTimeout(ctx, time.Duration(5)*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address, grpc.WithInsecure(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
	if err != nil {
		node.err = err
		clientConnChan <- node
	} else {
		node.rizzoClient = rizzopb.NewRizzoClient(conn)
		node.grpcConn = conn
		clientConnChan <- node
	}
}

func dialNodes(ctx context.Context, hosts []string) (map[string]*Node, map[string]*Node) {
	var node *Node
	clientConnChan := make(chan *Node)
	for _, host := range hosts {
		node = new(Node)
		node.host = host
		go grpcConnect(ctx, node, clientConnChan)
	}

	nodes := make(map[string]*Node)
	errNodes := make(map[string]*Node)
	for i := 0; i < len(hosts); i++ {
		node = <-clientConnChan
		if node.err != nil {
			errNodes[node.host] = node
		} else {
			nodes[node.host] = node
		}
	}
	return nodes, errNodes
}

func commitLogIdList(repo *git.Repository, beginRev string, endRev string) ([]git.Oid, map[git.Oid]*git.Commit, error) {
	var commitLogIds []git.Oid
	var commits map[git.Oid]*git.Commit

	commits = make(map[git.Oid]*git.Commit)

	rv, err := repo.Walk()
	if err != nil {
		return nil, nil, err
	}

	// We what to sort by the topology of the date of the commits. Also, reverse
	// the sort so the first commit in the array is the earliest commit or oldest
	// ancestor in the topology.
	rv.Sorting(git.SortTopological | git.SortReverse)

	endObj, err := gitutil.RevparseToCommit(endRev, repo)
	if err != nil {
		return nil, nil, err
	}
	err = rv.Push(endObj.Id())
	if err != nil {
		return nil, nil, err
	}
	beginObj, err := gitutil.RevparseToCommit(beginRev, repo)
	if err != nil {
		return nil, nil, err
	}
	err = rv.Hide(beginObj.Id())
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
	}
	return commitLogIds, commits, nil
}

func loadNoop(commit git.Oid, node *Node, noopDir string, repo *git.Repository, logger *log.Logger) (*rizzopb.PuppetReport, error) {
	emptyReport := new(rizzopb.PuppetReport)
	descendant, err := repo.DescendantOf(&node.lastApply, &commit)
	if err != nil {
		logger.Fatalf("Cannot determine descendant status: %v", err)
	}
	if descendant || node.lastApply.Equal(&commit) {
		logger.Printf("Commit already applied, substituting an empty noop: %s@%s", node.host, commit.String())
		return emptyReport, nil
	}

	reportPath := noopDir + "/" + node.host + "/" + commit.String() + ".json"
	if _, err := os.Stat(reportPath); err != nil {
		return nil, err
	}
	file, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	rprt := new(rizzopb.PuppetReport)
	err = json.Unmarshal([]byte(data), rprt)
	if err != nil {
		return nil, err
	}
	if node.host != rprt.Host {
		return nil, fmt.Errorf("Host mismatch %s != %s", node.host, rprt.Host)
	}
	// If the report status is failed, we may not have a LastApplyVersion field
	if rprt.Status == "failed" {
		return rprt, nil
	} else {
		// To accurately create delta noops the last applied version which the noop
		// is taken against must match between all the noops. If it does not some
		// diffs might not match.  For example if a file is edited before and after
		// an apply, a noop taken after the apply will only reflect the second
		// edit, whereas a noop taken before the apply will contain both edits. So
		// if the serialized noops lastApply does not match the host's current
		// lastApply we consider the noop invalid.
		applyStatus, oidPtr, err := parseLastApply(rprt.LastApplyVersion, repo)
		if err != nil {
			return nil, err
		}
		switch applyStatus {
		case lastApplyClean:
			if node.lastApply == *oidPtr {
				return rprt, nil
			} else {
				return nil, &noopInvalidError{node.host, node.lastApply, *oidPtr}
			}
		case lastApplyDirty:
			return nil, fmt.Errorf("Noop last apply for %s@%s was dirty!, '%s'", node.host, commit.String(), rprt.LastApplyVersion)
		case lastApplyErrored:
			return nil, fmt.Errorf("Noop last apply for %s@%s was unparseable!, '%s'", node.host, commit.String(), rprt.LastApplyVersion)
		default:
			return rprt, errors.New("Unknown lastApplyStatus!")
		}
	}
}

func normalizeReport(rprt rizzopb.PuppetReport, logger *log.Logger) rizzopb.PuppetReport {
	for _, resourceStatus := range rprt.ResourceStatuses {
		// Strip off the puppet confdir prefix, so we are left with the relative
		// path of the source file in the code repo
		if resourceStatus.File != "" {
			resourceStatus.File = strings.TrimPrefix(resourceStatus.File, rprt.Confdir+"/")
		}
	}
	rprt.Logs = normalizeLogs(rprt.Logs, logger)
	return rprt
}

func marshalReport(rprt rizzopb.PuppetReport, noopDir string, commit git.Oid) error {
	reportPath := noopDir + "/" + rprt.Host + "/" + commit.String() + ".json"
	data, err := json.Marshal(rprt)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(reportPath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}
func marshalGroupedReport(oid *git.Oid, gr groupedReport, groupedNoopDir string) error {
	groupedReportPath := groupedNoopDir + "/" + oid.String() + ".json"
	data, err := json.Marshal(gr)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(groupedReportPath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func unmarshalGroupedReport(oid *git.Oid, groupedNoopDir string) (groupedReport, error) {
	groupedReportPath := groupedNoopDir + "/" + oid.String() + ".json"
	file, err := os.Open(groupedReportPath)
	if err != nil {
		return groupedReport{}, err
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return groupedReport{}, err
	}
	var gr groupedReport
	err = json.Unmarshal([]byte(data), &gr)
	if err != nil {
		return groupedReport{}, err
	}
	return gr, nil
}

func noopNodeSet(ns *NodeSet, commitId git.Oid, repo *git.Repository, noopDir string, conf *HecklerdConf, logger *log.Logger) error {
	var err error
	var rprt *rizzopb.PuppetReport
	errNoopNodes := make(map[string]*Node)
	lockedByAnotherNoopNodes := make(map[string]*Node)
	puppetReportChan := make(chan applyResult)
	noopHosts := make(map[string]bool)
	for host, node := range ns.nodes.active {
		if rprt, err = loadNoop(commitId, node, noopDir, repo, logger); err == nil {
			ns.nodes.active[node.host].commitReports[commitId] = rprt
		} else if _, ok := err.(*noopInvalidError); ok || os.IsNotExist(err) {
			rizzoLockNode(
				rizzopb.PuppetLockRequest{
					Type:    rizzopb.LockReqType_lock,
					User:    "root",
					Comment: conf.LockMessage,
					Force:   false,
				},
				node)
			switch node.lockState.LockStatus {
			case heckler.LockedByAnother:
				lockedByAnotherNoopNodes[host] = node
				delete(ns.nodes.active, host)
				continue
			case heckler.LockUnknown:
				errNoopNodes[host] = node
				delete(ns.nodes.active, host)
				logger.Println(errNoopNodes[host].err)
				continue
			case heckler.LockedByUser:
				par := rizzopb.PuppetApplyRequest{Rev: commitId.String(), Noop: true}
				go hecklerApply(node, puppetReportChan, par)
				noopHosts[node.host] = true
			}
		} else {
			logger.Fatalf("Unable to load noop: %v", err)
		}
	}
	noopRequests := len(noopHosts)
	if noopRequests > 0 {
		logger.Printf("Requesting noops for %s: %s", commitId.String(), compressHostsMap(noopHosts))
	}
	for j := 0; j < noopRequests; j++ {
		logger.Printf("Waiting for (%d) outstanding noop requests: %s", noopRequests-j, compressHostsMap(noopHosts))
		r := <-puppetReportChan
		rizzoLockNode(
			rizzopb.PuppetLockRequest{
				Type:  rizzopb.LockReqType_unlock,
				User:  "root",
				Force: false,
			}, ns.nodes.active[r.host])
		if ns.nodes.active[r.host].lockState.LockStatus != heckler.Unlocked {
			logger.Printf("Unlock of %s failed", r.host)
		}
		if r.err != nil {
			ns.nodes.active[r.host].err = fmt.Errorf("Noop failed: %w", r.err)
			errNoopNodes[r.host] = ns.nodes.active[r.host]
			logger.Println(errNoopNodes[r.host].err)
			delete(ns.nodes.active, r.host)
			delete(noopHosts, r.host)
			continue
		}
		newRprt := normalizeReport(r.report, logger)
		// Failed reports are created by rizzod, so they lack the Host field
		// which is set by Puppet
		if newRprt.Status == "failed" {
			newRprt.Host = r.host
		}
		logger.Printf("Received noop: %s@%s", newRprt.Host, newRprt.ConfigurationVersion)
		delete(noopHosts, newRprt.Host)
		commitId, err := git.NewOid(newRprt.ConfigurationVersion)
		if err != nil {
			logger.Fatalf("Unable to convert ConfigurationVersion to a git oid: %v", err)
		}
		ns.nodes.active[newRprt.Host].commitReports[*commitId] = &newRprt
		err = marshalReport(newRprt, noopDir, *commitId)
		if err != nil {
			logger.Fatalf("Unable to marshal report: %v", err)
		}
	}
	ns.nodes.errored = mergeNodeMaps(ns.nodes.errored, errNoopNodes)
	ns.nodes.lockedByAnother = mergeNodeMaps(ns.nodes.lockedByAnother, lockedByAnotherNoopNodes)
	if ok := thresholdExceededNodeSet(ns, logger); ok {
		return ErrThresholdExceeded
	}
	return nil
}

func groupReportNodeSet(ns *NodeSet, commit *git.Commit, deltaNoop bool, repo *git.Repository, conf *HecklerdConf, logger *log.Logger) (groupedReport, error) {
	var err error
	for host, _ := range ns.nodes.active {
		os.Mkdir(conf.NoopDir+"/"+host, 0755)
	}

	// If the commit is not part of every nodes lineage we are unable to create a
	// deltaNoop, since we can't subtract the parents as the parents would not
	// necessarily include changes from the parents children
	//
	// If some node's lastApply is commit B we can't subtract commit A's noop from C since
	// it would not include the changes introduced by commit B.
	//
	// * commit D
	// |\
	// | * commit C
	// * | commit B
	// |/
	// * commit A
	//
	if deltaNoop && !commitInAllNodeLineages(*commit.Id(), ns.nodes.active, repo, logger) {
		return groupedReport{CommitNotInAllNodeLineages: true}, nil
	}

	commitIdsToNoop := make([]git.Oid, 0)
	commitIdsToNoop = append(commitIdsToNoop, *commit.Id())

	parentCount := commit.ParentCount()
	for i := uint(0); i < parentCount; i++ {
		// There are two cases where we do not want a noop:
		// 1. `deltaNoop == false`, we substitute empty noops so that we subtract
		//     nothing
		// 1. `commitInAllNodeLineages(*commit.ParentId(i), ...) == false` we can't
		//     noop a commit that is not in the lineage of all nodes for the reason
		//     noted above, so we substitute an empty noop
		if deltaNoop && commitInAllNodeLineages(*commit.ParentId(i), ns.nodes.active, repo, logger) {
			commitIdsToNoop = append(commitIdsToNoop, *commit.ParentId(i))
		} else {
			for _, node := range ns.nodes.active {
				node.commitReports[*commit.ParentId(i)] = &rizzopb.PuppetReport{}
				node.commitDeltaResources[*commit.ParentId(i)] = make(map[ResourceTitle]*deltaResource)
			}
		}
	}

	for _, commitId := range commitIdsToNoop {
		err = noopNodeSet(ns, commitId, repo, conf.NoopDir, conf, logger)
		if err != nil {
			return groupedReport{}, err
		}
	}

	var ge []*groupedError
	groupedParentEvalErrors := &groupedError{
		Type:  "ParentEvalError",
		Error: "An evaluation error occured in a parent commit, stopping the creation of a delta noop.",
	}
	EvalErrorNodes := make(map[string]*Node)
	for host, node := range ns.nodes.active {
		if node.commitReports[*commit.Id()].Status == "failed" {
			EvalErrorNodes[host] = node
			delete(ns.nodes.active, host)
			continue
		}
		parentEvalErrors, parentReports := commitParentReports(*commit, node.lastApply, node.commitReports, node.host, repo, logger)
		if parentEvalErrors {
			groupedParentEvalErrors.Hosts = append(groupedParentEvalErrors.Hosts, host)
			delete(ns.nodes.active, host)
			continue
		}
		logger.Printf("Creating delta resource for commit %s@%s", node.host, commit.Id().String())
		delta, err := subtractNoops(node.commitReports[*commit.Id()], parentReports, conf.IgnoredResources)
		if err != nil {
			return groupedReport{}, err
		}
		node.commitDeltaResources[*commit.Id()] = delta
	}
	if len(groupedParentEvalErrors.Hosts) > 0 {
		ge = append(ge, groupedParentEvalErrors)
	}

	logger.Printf("Grouping commit %s", commit.Id().String())
	groupedResources := make([]*groupedResource, 0)
	for _, node := range ns.nodes.active {
		for _, nodeDeltaRes := range node.commitDeltaResources[*commit.Id()] {
			groupedResources = append(groupedResources, groupResources(*commit.Id(), nodeDeltaRes, ns.nodes.active, conf))
		}
	}
	for _, node := range EvalErrorNodes {
		for _, puppetLog := range node.commitReports[*commit.Id()].Logs {
			if puppetLog.Source == "EvalError" {
				ge = append(ge, groupEvalErrors(*commit.Id(), puppetLog, EvalErrorNodes))
			}
		}
	}
	ge = append(ge, groupErrorNodes(ns.nodes.errored)...)
	beyondRevNodes := make(map[string]*Node)
	for host, node := range ns.nodes.active {
		if commitAlreadyApplied(node.lastApply, *commit.Id(), repo) {
			beyondRevNodes[host] = node
		}
	}
	gr := groupedReport{
		Resources:       groupedResources,
		Errors:          ge,
		BeyondRev:       groupBeyondRevNodes(beyondRevNodes),
		LockedByAnother: groupLockNodes(ns.nodes.lockedByAnother),
	}
	return gr, nil
}

func priorEvent(event *rizzopb.Event, resourceTitleStr string, priorCommitNoops []*rizzopb.PuppetReport) bool {
	for _, priorCommitNoop := range priorCommitNoops {
		if priorCommitNoop == nil {
			log.Fatalf("Error: prior commit noop was nil!")
		}
		if priorCommitNoop.ResourceStatuses == nil {
			continue
		}
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

func priorLog(curLog *rizzopb.Log, priorCommitNoops []*rizzopb.PuppetReport) bool {
	for _, priorCommitNoop := range priorCommitNoops {
		if priorCommitNoop == nil {
			log.Fatalf("Error: prior commit noop was nil!")
		}
		if priorCommitNoop.Logs == nil {
			continue
		}
		for _, priorLog := range priorCommitNoop.Logs {
			if *curLog == *priorLog {
				return true
			}
		}
	}
	return false
}

func initDeltaResource(resourceTitle ResourceTitle, r *rizzopb.ResourceStatus, deltaEvents []*rizzopb.Event, deltaLogs []*rizzopb.Log) *deltaResource {
	deltaRes := new(deltaResource)
	deltaRes.Title = resourceTitle
	deltaRes.Type = r.ResourceType
	deltaRes.Events = deltaEvents
	deltaRes.Logs = deltaLogs
	deltaRes.DefineType = resourceDefineType(r)
	deltaRes.File = r.File
	deltaRes.Line = r.Line
	deltaRes.ContainmentPath = r.ContainmentPath
	return deltaRes
}

func subtractNoops(commitNoop *rizzopb.PuppetReport, priorCommitNoops []*rizzopb.PuppetReport, ignoredResources []IgnoredResources) (map[ResourceTitle]*deltaResource, error) {
	var deltaEvents []*rizzopb.Event
	var deltaLogs []*rizzopb.Log
	var deltaResources map[ResourceTitle]*deltaResource
	var resourceTitle ResourceTitle

	deltaResources = make(map[ResourceTitle]*deltaResource)

	if commitNoop.ResourceStatuses == nil {
		return deltaResources, nil
	}

	for resourceTitleStr, r := range commitNoop.ResourceStatuses {
		ignored, err := resourceIgnored(resourceTitleStr, ignoredResources)
		if err != nil {
			return nil, err
		}
		if ignored {
			continue
		}
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

	return deltaResources, nil
}

// Determine if a commit is already applied based on the last appliedCommit.
// If the potentialCommit is an ancestor of the appliedCommit or equal to the
// appliedCommit then we know the potentialCommit has already been applied.
func commitAlreadyApplied(appliedCommit git.Oid, potentialCommit git.Oid, repo *git.Repository) bool {
	if appliedCommit.Equal(&potentialCommit) {
		return true
	}
	descendant, err := repo.DescendantOf(&appliedCommit, &potentialCommit)
	if err != nil {
		log.Fatalf("Cannot determine descendant status: %v", err)
	}
	return descendant