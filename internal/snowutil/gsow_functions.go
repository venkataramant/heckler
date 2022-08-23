package snowutil

import (
	gsnow "github.braintreeps.com/braintree/heckler-plugins/gsnow"
)

func _moveChangeRequestToImplement(gsnowMGR gsnow.GSNOWManager, changeRequestID string) (bool, error) {
	comments := "moving change Request to Implement state"
	state := "Implement"
	return _checkInChangeRequest(gsnowMGR, changeRequestID, comments, state)
}
func _scheduleChangeRequest(gsnowMGR gsnow.GSNOWManager, changeRequestID string) (bool, error) {
	comments := "moving change Request to Scheduled state"
	state := "Scheduled"
	return _checkInChangeRequest(gsnowMGR, changeRequestID, comments, state)

}

func _updateChangeRequest(gsnowMGR gsnow.GSNOWManager, changeRequestID, comments string) (bool, error) {
	isUpdated, err2 := gsnowMGR.UpdateChangeRequest(changeRequestID, comments)
	return isUpdated, err2

}

func _checkInChangeRequest(gsnowMGR gsnow.GSNOWManager, changeRequestID, comments, state string) (bool, error) {
	isCheckedIn, err2 := gsnowMGR.CheckInChangeRequest(changeRequestID, comments, state)
	return isCheckedIn, err2

}

func _checkInChangeTask(gsnowMGR gsnow.GSNOWManager, parentID, taskNumber string) (bool, error) {
	workNotes := "Checkin Task"
	isUpdated, err2 := gsnowMGR.CheckInChangeTask(parentID, taskNumber, workNotes)
	return isUpdated, err2

}
func _signOffChangeTask(gsnowMGR gsnow.GSNOWManager, parentID, taskNo string) (bool, error) {
	workNotes := "Closed Task "
	state := "Closed Complete"
	isUpdated, err2 := gsnowMGR.SignoffChangeTask(parentID, taskNo, workNotes, state)
	return isUpdated, err2

}

func _GetChangeTasks(gsnowMGR gsnow.GSNOWManager, changeRequestID string) ([]gsnow.ChangeTaskData, error) {
	return gsnowMGR.GetChangeTasks(changeRequestID)

}
