package snow_plugin

import (
	"flag"
	"fmt"
	"log"
	"plugin"
)

const DEFAULT_PLUGIN_PATH = "/etc/hecklerd/gsnow_plugin.so"
const DEFAULT_PLUGIN_PATH2 = "./gsnow_plugin.so"

var pluginPath = flag.String("plugin_path", DEFAULT_PLUGIN_PATH, "Please provide plugin path")

type SNowPluginManager struct {
	gsnowPlugin *plugin.Plugin
}

func GetSNowPluginManager(pluginPath string) (SNowPluginManager, error) {
	var emptySNowPluginManager SNowPluginManager
	log.Printf(" plugin_path::%s \n", pluginPath)
	gsnowPlugin, err := plugin.Open(pluginPath)
	if err != nil {
		fmt.Printf("plugin.Open error::%v\n", err)
		return emptySNowPluginManager, err
	}

	snowPlugingMGR := SNowPluginManager{gsnowPlugin: gsnowPlugin}
	return snowPlugingMGR, nil
}

func (snowPlugingMGR SNowPluginManager) SearchAndCreateChangeRequest(env, tag string) (string, error) {
	f_CreateCR, f_CreateCRErr := snowPlugingMGR.gsnowPlugin.Lookup("SearchAndCreateChangeRequestFunc")
	if f_CreateCRErr != nil {
		fmt.Printf("gsnowPlugin.Lookup for SearchAndCreateChangeRequestFunc error::%v\n", f_CreateCRErr)
		return "", f_CreateCRErr
	}

	changeRequestID, changeRequestError := f_CreateCR.(func(string, string) (string, error))(env, tag)
	log.Println("this is result from f_CreateCR", changeRequestID, changeRequestError)
	return changeRequestID, changeRequestError
}
func (snowPlugingMGR SNowPluginManager) GetChangeRequestDetails(changeRequestID string) (string, error) {
	f_GetCR, f_GetCRErr := snowPlugingMGR.gsnowPlugin.Lookup("GetChangeRequestDetailsFunc")
	if f_GetCRErr != nil {
		fmt.Printf("gsnowPlugin.Lookup for GetChangeRequestDetailsFunc error::%v\n", f_GetCRErr)
		return "", f_GetCRErr
	}
	crJson, crError := f_GetCR.(func(string) (string, error))(changeRequestID)
	log.Println("this is result from f_GetCR", crJson, crError)
	return crJson, crError
}

func (snowPlugingMGR SNowPluginManager) CommentChangeRequest(changeRequestID, comment string) (bool, error) {
	f_CommentCR, f_CommentCRErr := snowPlugingMGR.gsnowPlugin.Lookup("CommentChangeRequestFunc")
	if f_CommentCRErr != nil {
		fmt.Printf("gsnowPlugin.Lookup for CommentChangeRequestFunc error::%v\n", f_CommentCRErr)
		return false, f_CommentCRErr
	}
	isCommented, commentError := f_CommentCR.(func(string, string) (bool, error))(changeRequestID, comment)
	log.Println("this is result from f_CommentCR", isCommented, commentError)
	return isCommented, commentError

}

func (snowPlugingMGR SNowPluginManager) CheckInChangeRequest(changeRequestID string) (bool, error) {

	f_CheckinCR, f_CheckinCRError := snowPlugingMGR.gsnowPlugin.Lookup("CheckInChangeRequestFunc")
	if f_CheckinCRError != nil {
		fmt.Printf("gsnowPlugin.Lookup for CheckInChangeRequestFunc error::%v\n", f_CheckinCRError)
		return false, f_CheckinCRError
	}
	isCheckedin, checkinError := f_CheckinCR.(func(string) (bool, error))(changeRequestID)
	log.Println("this is result from f_CheckinCR", isCheckedin, checkinError)
	return isCheckedin, checkinError

}

func (snowPlugingMGR SNowPluginManager) SignOffChangeRequest(changeRequestID string) (bool, error) {
	f_signoffCR, f_signoffCRerr := snowPlugingMGR.gsnowPlugin.Lookup("SignOffChangeRequestFunc")
	if f_signoffCRerr != nil {
		fmt.Printf("gsnowPlugin.Lookup for SignOffChangeRequestFunc SignOffChangeRequestFunc::%v\n", f_signoffCRerr)
		return false, f_signoffCRerr
	}
	isSignedOff, signedError := f_signoffCR.(func(string) (bool, error))(changeRequestID)
	log.Println("this is result from f_signoffCR", isSignedOff, signedError)
	return isSignedOff, signedError

}
