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
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/pkg/errors"
)

// AssociationsResponse defines the schema for the associations response JSON object
type AssociationsResponse struct {
	Associations []string `json:"Associations"`
}

// AssociationResponse defines the schema for the association response JSON object
type AssociationResponse struct {
	Name     string `json:"Name"`
	Encoding string `json:"Encoding"`
	Value    string `json:"Value"`
}

func newAssociationsResponse(containerID, taskARN, associationType string, state dockerstate.TaskEngineState) (*AssociationsResponse, error) {
	dockerContainer, ok := state.ContainerByID(containerID)
	if !ok {
		return nil, errors.Errorf("unable to get container name from docker id: %s", containerID)
	}
	containerName := dockerContainer.Container.Name

	task, ok := state.TaskByArn(taskARN)
	if !ok {
		return nil, errors.Errorf("unable to get task from task arn: %s", taskARN)
	}

	associationNames := task.AssociationsByTypeAndContainer(associationType, containerName)

	return &AssociationsResponse{
		Associations: associationNames,
	}, nil
}

func newAssociationResponse(taskARN, associationType, associationName string, state dockerstate.TaskEngineState) (*AssociationResponse, error) {
	task, ok := state.TaskByArn(taskARN)
	if !ok {
		return nil, errors.Errorf("unable to get task from task arn: %s", taskARN)
	}

	association, ok := task.AssociationByTypeAndName(associationType, associationName)

	if !ok {
		return nil, errors.Errorf("unable to get association from association type %s and association name %s", associationType, associationName)
	}

	return &AssociationResponse{
		Name:     association.Name,
		Encoding: association.Content.Encoding,
		Value:    association.Content.Value,
	}, nil
}
