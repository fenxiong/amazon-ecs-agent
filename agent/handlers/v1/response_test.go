// +build unit

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package v1

import (
	"encoding/json"
	"testing"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apieni "github.com/aws/amazon-ecs-agent/agent/api/eni"
	apitask "github.com/aws/amazon-ecs-agent/agent/api/task"
	apitaskstatus "github.com/aws/amazon-ecs-agent/agent/api/task/status"
	"github.com/stretchr/testify/assert"
)

const (
	taskARN        = "t1"
	family         = "sleep"
	version        = "1"
	containerID    = "cid"
	containerName  = "sleepy"
	eniIPv4Address = "10.0.0.2"
)

func TestTaskResponse(t *testing.T) {
	expectedTaskResponseMap := map[string]interface{}{
		"Arn":           "t1",
		"DesiredStatus": "RUNNING",
		"KnownStatus":   "RUNNING",
		"Family":        "sleep",
		"Version":       "1",
		"Containers": []interface{}{
			map[string]interface{}{
				"DockerId":   "cid",
				"DockerName": "sleepy",
				"Name":       "sleepy",
				"Ports": []interface{}{
					map[string]interface{}{
						// The number should be float here, because when we unmarshal
						// something and we don't specify the number type, it will be
						// set to float.
						"ContainerPort": float64(80),
						"Protocol":      "tcp",
						"HostPort":      float64(80),
					},
				},
				"Networks": []interface{}{
					map[string]interface{}{
						"NetworkMode":   "awsvpc",
						"IPv4Addresses": []interface{}{"10.0.0.2"},
					},
				},
			},
		},
	}

	task := &apitask.Task{
		Arn:                 taskARN,
		Family:              family,
		Version:             version,
		DesiredStatusUnsafe: apitaskstatus.TaskRunning,
		KnownStatusUnsafe:   apitaskstatus.TaskRunning,
		ENI: &apieni.ENI{
			IPV4Addresses: []*apieni.ENIIPV4Address{
				{
					Address: eniIPv4Address,
				},
			},
		},
	}

	container := &apicontainer.Container{
		Name: containerName,
		Ports: []apicontainer.PortBinding{
			{
				ContainerPort: 80,
				Protocol:      apicontainer.TransportProtocolTCP,
			},
		},
	}

	containerNameToDockerContainer := map[string]*apicontainer.DockerContainer{
		taskARN: {
			DockerID:   containerID,
			DockerName: containerName,
			Container:  container,
		},
	}

	taskResponse := NewTaskResponse(task, containerNameToDockerContainer)

	taskResponseJSON, err := json.Marshal(taskResponse)
	assert.NoError(t, err)

	taskResponseMap := make(map[string]interface{})

	json.Unmarshal(taskResponseJSON, &taskResponseMap)

	assert.Equal(t, expectedTaskResponseMap, taskResponseMap)
}

func TestContainerResponse(t *testing.T) {
	expectedContainerResponseMap := map[string]interface{}{
		"DockerId":   "cid",
		"DockerName": "sleepy",
		"Name":       "sleepy",
		"Ports": []interface{}{
			map[string]interface{}{
				"ContainerPort": float64(80),
				"Protocol":      "tcp",
				"HostPort":      float64(80),
			},
		},
		"Networks": []interface{}{
			map[string]interface{}{
				"NetworkMode":   "awsvpc",
				"IPv4Addresses": []interface{}{"10.0.0.2"},
			},
		},
	}

	container := &apicontainer.Container{
		Name: containerName,
		Ports: []apicontainer.PortBinding{
			{
				ContainerPort: 80,
				Protocol:      apicontainer.TransportProtocolTCP,
			},
		},
	}

	dockerContainer := &apicontainer.DockerContainer{
		DockerID:   containerID,
		DockerName: containerName,
		Container:  container,
	}

	eni := &apieni.ENI{
		IPV4Addresses: []*apieni.ENIIPV4Address{
			{
				Address: eniIPv4Address,
			},
		},
	}

	containerResponse := NewContainerResponse(dockerContainer, eni)

	containerResponseJSON, err := json.Marshal(containerResponse)
	assert.NoError(t, err)

	containerResponseMap := make(map[string]interface{})

	json.Unmarshal(containerResponseJSON, &containerResponseMap)

	assert.Equal(t, expectedContainerResponseMap, containerResponseMap)
}

func TestPortBindingsResponse(t *testing.T) {
	container := &apicontainer.Container{
		Name: containerName,
		Ports: []apicontainer.PortBinding{
			{
				ContainerPort: 80,
				HostPort:      80,
				Protocol:      apicontainer.TransportProtocolTCP,
			},
		},
	}

	dockerContainer := &apicontainer.DockerContainer{
		Container: container,
	}

	PortBindingsResponse := NewPortBindingsResponse(dockerContainer, nil)

	assert.Equal(t, uint16(80), PortBindingsResponse[0].ContainerPort)
	assert.Equal(t, uint16(80), PortBindingsResponse[0].HostPort)
	assert.Equal(t, "tcp", PortBindingsResponse[0].Protocol)
}
