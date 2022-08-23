package snowutil

import (
	"errors"
	"fmt"
	gsnow "github.braintreeps.com/braintree/heckler-plugins/gsnow"
	"log"
	"os"
	"time"
)

func getSNOWMGR() (gsnow.GSNOWManager, error) {
	token := os.Getenv("GSNOW_TOKEN")
	if token == "" {
		var emptyMGR gsnow.GSNOWManager
		msg := "NO SNNOW TOKEN found in ENV"
		fmt.Println(msg)
		return emptyMGR, errors.New(msg)
	}
	gnowAPIURL := "https://eshome-qa.es.paypalcorp.com/gsnow"
	authUser := ""
	proxyURL := ""
	credMap := make(map[string]string)
	configMap := make(map[string]string)
	credMap["token"] = token
	configMap["ASSIGNED_TO"] = "api_bo9pace"
	gsnowMGR, err1 := gsnow.GetGSNOWManager(gnowAPIURL, authUser, proxyURL, configMap, credMap)
	return gsnowMGR, err1
}
func SearchAndCreateChangeRequest(tag string) (string, error) {
	return CreateChangeRequest(tag)
}

func CreateChangeRequest(tag string) (string, error) {
	gsnowMGR, mgrError := getSNOWMGR()
	if mgrError != nil {
		return "", mgrError
	}
	fmt.Print("gsnowMGR is \n", gsnowMGR)
	currentTime := gsnow.GetPST() //time.Now()
	startDate := currentTime.Add(time.Minute * 1)
	// 	startDateString := startDate.UTC().Format(SN_TIME_LAYOUT)
	startDateString := startDate.Format(gsnow.SN_TIME_LAYOUT)
	endDate := currentTime.Add(time.Hour * 24)
	endDateString := endDate.Format(gsnow.SN_TIME_LAYOUT)
	// 	time.RFC3339)
	description := "Heckler Puppet Applied for Tag::" + tag
	log.Println("description::", description, "startDateString::", startDateString, "endDateString::", endDateString)
	createTicketData := make(map[string]interface{})
	createTicketData["backout_plan"] = "Team follows SPOC"
	createTicketData["priority"] = 4
	createTicketData["implementation_plan"] = "Use Heckler to apply puppet changes"
	createTicketData["justifications"] = "justifications from commit"
	createTicketData["requested_by"] = "api_bo9pace"
	createTicketData["modified_by"] = "api_bo9pace"
	createTicketData["assigned_to"] = "api_bo9pace"
	createTicketData["risk"] = "low"
	createTicketData["start_date"] = startDateString
	createTicketData["end_date"] = endDateString
	createTicketData["duration"] = 1440
	createTicketData["test_plan"] = "Used Heckler and applied puppet changes in QA"
	createTicketData["type"] = "Standard"
	createTicketData["atb_cust_impact"] = 0
	createTicketData["service_category"] = "Administration" //"Puppet-OPS"
	createTicketData["category_type"] = "Upgrade"
	createTicketData["category_sub_type"] = "Infrastructure"
	createTicketData["deployment_category"] = "Config"
	createTicketData["environment"] = "Development"
	createTicketData["impacted_site"] = "PayPal"
	createTicketData["site_components"] = "Braintree"
	createTicketData["site_impact"] = "Braintree"
	createTicketData["assigned_group"] = "BT Heckler-Automation"
	createTicketData["description"] = description
	createTicketData["short_description"] = description
	createTicketData["availability_zone"] = "Braintree"
	createTicketData["AssignedTo"] = "api_bo9pace"
	createTicketData["deployment_vehicle"] = "Heckler"

	isTicketCreated, changeRequestID, createError := gsnowMGR.CreateChangeRequest(createTicketData)
	fmt.Println("gsnowMGR.CreateChangeRequest returned", isTicketCreated, changeRequestID, createError)
	return changeRequestID, createError

}

func CommentChangeRequest(changeRequestID, comments string) (bool, error) {
	gsnowMGR, mgrError := getSNOWMGR()
	if mgrError != nil {
		return false, mgrError
	}
	return _updateChangeRequest(gsnowMGR, changeRequestID, comments)
}
func CheckInChangeRequest(changeRequestID string) (bool, error) {
	gsnowMGR, mgrError := getSNOWMGR()
	if mgrError != nil {
		return false, mgrError
	}

	isTicketScheduled, scheduleError := _scheduleChangeRequest(gsnowMGR, changeRequestID)

	if scheduleError == nil {
		fmt.Print("isTicketScheduled is  ", isTicketScheduled, "\n")
		time.Sleep(time.Minute * 2)
		isTicketMovedToImplement, implementError := _moveChangeRequestToImplement(gsnowMGR, changeRequestID)

		if implementError == nil {
			fmt.Print("isTicketMovedToImplement is  ", isTicketMovedToImplement, "\n")
			changeTasks, getTasksError := _GetChangeTasks(gsnowMGR, changeRequestID)

			if getTasksError == nil {
				for index, changeTask := range changeTasks {
					taskNumber := changeTask.Number
					log.Println("CheckInTask #", index, " TaskNumber::", taskNumber)
					isTaskCheckedIn, taskCheckedError := _checkInChangeTask(gsnowMGR, changeRequestID, taskNumber)
					log.Println("CheckedInTaskStatus #", index, " TaskNumber::", taskNumber, isTaskCheckedIn)
					if taskCheckedError == nil {
						isTaskSignedOff, taskSignedOffError := _signOffChangeTask(gsnowMGR, changeRequestID, taskNumber)
						log.Println("SignOffTask #", index, " TaskNumber::", taskNumber)

						if taskSignedOffError != nil {
							fmt.Printf("Unable to invoke _signOffChangeTask::%v\n", taskSignedOffError)
							return false, taskSignedOffError
						}
						log.Println("SignedOffTaskStatus #", index, " TaskNumber::", taskNumber, isTaskSignedOff)

					} else {
						fmt.Printf("Unable to invoke _checkInChangeTask::%v\n", taskCheckedError)
						return false, taskCheckedError
					}

				}

			} else {
				fmt.Printf("Unable to invoke _GetChangeTasks::%v\n", getTasksError)
				return false, getTasksError
			}

		} else {
			fmt.Printf("Unable to invoke _moveChangeRequestToImplement::%v\n", implementError)
			return false, implementError
		}

	} else {
		fmt.Printf("Unable to invoke _scheduleChangeRequest::%v\n", scheduleError)
		return false, scheduleError
	}
	return true, nil
}

func SignOffChangeRequest(changeRequestID string) (bool, error) {
	comments := "moving change Request to Close state by Heckler"
	closeCode := "Successful"
	closeNotes := "Closed Ticket by Heckler"
	state := "Closed"
	gsnowMGR, mgrError := getSNOWMGR()
	if mgrError != nil {
		return false, mgrError
	}
	isSignedOff, err2 := gsnowMGR.SignOffChangeRequest(changeRequestID, comments, closeNotes, closeCode, state)
	return isSignedOff, err2

}
