// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package v3

import (
	"encoding/json"
	"fmt"
	"github.com/aws/amazon-ecs-agent/agent/statemanager"
	"github.com/pkg/errors"
	"net/http"

	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/aws/amazon-ecs-agent/agent/handlers/utils"
	"github.com/cihub/seelog"
)

const (
	// associationTypeMuxName is the key that's used in gorilla/mux to get the association type.
	associationTypeMuxName = "associationTypeMuxName"
	// associationNameMuxName is the key that's used in gorilla/mux to get the association name.
	associationNameMuxName = "associationNameMuxName"
)

var (
	// Container associations endpoint: /v3/<v3 endpoint id>/<association type>
	ContainerAssociationsPath = fmt.Sprintf("/v3/%s/associations/%s",
		utils.ConstructMuxVar(v3EndpointIDMuxName, utils.AnythingButSlashRegEx),
		utils.ConstructMuxVar(associationTypeMuxName, utils.AnythingButSlashRegEx))
	// Container association endpoint: /v3/<v3 endpoint id>/<association type>/<association name>
	ContainerAssociationPath = fmt.Sprintf("/v3/%s/associations/%s/%s",
		utils.ConstructMuxVar(v3EndpointIDMuxName, utils.AnythingButSlashRegEx),
		utils.ConstructMuxVar(associationTypeMuxName, utils.AnythingButSlashRegEx),
		utils.ConstructMuxVar(associationNameMuxName, utils.AnythingButSlashRegEx))
	// Treat "/v3/<v3 endpoint id>/<association type>/" as a container association endpoint with empty association name (therefore invalid), to be consistent with similar situation in credentials endpoint and v3 metadata endpoint
	ContainerAssociationPathWithSlash = ContainerAssociationsPath + "/"
	ContainerAssociationHealthPath = fmt.Sprintf("/v3/%s/associations/%s/%s/health",
		utils.ConstructMuxVar(v3EndpointIDMuxName, utils.AnythingButSlashRegEx),
		utils.ConstructMuxVar(associationTypeMuxName, utils.AnythingButSlashRegEx),
		utils.ConstructMuxVar(associationNameMuxName, utils.AnythingButSlashRegEx))
)

// ContainerAssociationHandler returns the handler method for handling container associations requests.
func ContainerAssociationsHandler(state dockerstate.TaskEngineState) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		containerID, err := getContainerIDByRequest(r, state)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: unable to get container id from request: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociations)
			return
		}

		taskARN, err := getTaskARNByRequest(r, state)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: unable to get task arn from request: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociations)
			return
		}

		associationType, err := getAssociationTypeByRequest(r)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociations)
			return
		}

		seelog.Infof("V3 container associations handler: writing response for container '%s' for association type %s", containerID, associationType)

		writeContainerAssociationsResponse(w, containerID, taskARN, associationType, state)
	}
}

// ContainerAssociationHandler returns the handler method for handling container association requests.
func ContainerAssociationHandler(state dockerstate.TaskEngineState) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		taskARN, err := getTaskARNByRequest(r, state)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: unable to get task arn from request: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociation)
			return
		}

		associationType, err := getAssociationTypeByRequest(r)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociation)
			return
		}

		associationName, err := getAssociationNameByRequest(r)
		if err != nil {
			responseJSON, _ := json.Marshal(
				fmt.Sprintf("V3 container associations handler: %s", err.Error()))
			utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, utils.RequestTypeContainerAssociation)
			return
		}

		seelog.Infof("V3 container association handler: writing response for association '%s' of type %s", associationName, associationType)

		writeContainerAssociationResponse(w, taskARN, associationType, associationName, state)
	}
}

func ContainerAssociationHealthHandler(state dockerstate.TaskEngineState, stateSaver statemanager.Saver) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		seelog.Infof("Receive health request: %+v", r)

		// get association from request
		taskARN, err := getTaskARNByRequest(r, state)
		if err != nil {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth, err, w)
			return
		}

		associationType, err := getAssociationTypeByRequest(r)
		if err != nil {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth, err, w)
			return
		}

		associationName, err := getAssociationNameByRequest(r)
		if err != nil {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth, err, w)
			return
		}

		task, ok := state.TaskByArn(taskARN)
		if !ok {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth,
				errors.Errorf("unable to get task from task arn: %s", taskARN), w)
			return
		}

		association, ok := task.AssociationByTypeAndName(associationType, associationName)
		if !ok {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth,
				errors.Errorf("unable to get association from association type %s and name %s", associationType,
					associationName), w)
		}

		// get container from request
		containerID, err := getContainerIDByRequest(r, state)
		if err != nil {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth, err, w)
			return
		}

		container, ok := state.ContainerByID(containerID)
		if !ok {
			writeFailureResponse(utils.RequestTypeContainerAssociationHealth,
				errors.Errorf("unable to get container from container id: %s", containerID), w)
			return
		}

		containerName := container.Container.Name
		seelog.Infof("Receive container health request from container '%s'", containerName)

		if containerName !=  "healthcheck" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		seelog.Infof("Before updating health status, task association: %s", task.Associations[0].String())

		healthStatus := r.Form.Get("healthStatus")
		seelog.Infof("Trying to update health status of association '%s' to '%s'", association.Name, healthStatus)
		task.UpdateAssociationHealth(associationType, associationName, healthStatus)

		seelog.Infof("After updating health status, task association: %s", task.Associations[0].String())

		err = stateSaver.ForceSave()
		seelog.Infof("Save err: %v", err)
		
		w.WriteHeader(http.StatusOK)
		return

		// get associated EIA with this container

		// if association not match, return 403 forbidden

		// return 200 ok with debug message
	}
}

func writeFailureResponse(requestType string, err error, w http.ResponseWriter) {
	responseJSON, _ := json.Marshal(fmt.Sprintf("%s request handler: %s", requestType, err.Error()))
	utils.WriteJSONToResponse(w, http.StatusBadRequest, responseJSON, requestType)
}

func writeContainerAssociationsResponse(w http.ResponseWriter, containerID, taskARN, associationType string, state dockerstate.TaskEngineState) {
	associationsResponse, err := newAssociationsResponse(containerID, taskARN, associationType, state)
	if err != nil {
		errResponseJSON, _ := json.Marshal(fmt.Sprintf("Unable to write container associations response: %s", err.Error()))
		utils.WriteJSONToResponse(w, http.StatusBadRequest, errResponseJSON, utils.RequestTypeContainerAssociations)
		return
	}

	responseJSON, _ := json.Marshal(associationsResponse)
	utils.WriteJSONToResponse(w, http.StatusOK, responseJSON, utils.RequestTypeContainerAssociations)
}

func writeContainerAssociationResponse(w http.ResponseWriter, taskARN, associationType, associationName string, state dockerstate.TaskEngineState) {
	associationResponse, err := newAssociationResponse(taskARN, associationType, associationName, state)
	if err != nil {
		errResponseJSON, _ := json.Marshal(fmt.Sprintf("Unable to write container association response: %s", err.Error()))
		utils.WriteJSONToResponse(w, http.StatusBadRequest, errResponseJSON, utils.RequestTypeContainerAssociation)
		return
	}

	// associationResponse is assumed to be a valid json string; see comments on newAssociationResponse method for details
	utils.WriteJSONToResponse(w, http.StatusOK, []byte(associationResponse), utils.RequestTypeContainerAssociation)
}
