// +build unit

// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package handler

import (
	"testing"
	"time"

	apieni "github.com/aws/amazon-ecs-agent/agent/api/eni"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/aws/amazon-ecs-agent/agent/statemanager"
)

const (
	attachmentArn = "attachmentarn"
)

// TestTaskENIAckTimeout tests acknowledge timeout for a regular eni before submit the state change
func TestTaskENIAckTimeout(t *testing.T) {
	testENIAckTimeout(t, apieni.ENIAttachmentTypeENI)
}

// TestTrunkENIAckTimeout tests acknowledge timeout for a trunk eni before submit the state change
func TestTrunkENIAckTimeout(t *testing.T) {
	testENIAckTimeout(t, apieni.ENIAttachmentTypeTrunkENI)
}

func testENIAckTimeout(t *testing.T, attachmentType string) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	taskEngineState := dockerstate.NewTaskEngineState()

	expiresAt := time.Now().Add(time.Duration(waitTimeoutMillis) * time.Millisecond)
	err := addENIAttachmentToState(attachmentType, attachmentArn, taskArn, randomMAC, expiresAt, taskEngineState)
	assert.NoError(t, err)
	assert.Len(t, taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments(), 1)
	for {
		time.Sleep(time.Millisecond * waitTimeoutMillis)
		if len(taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments()) == 0 {
			break
		}
	}
}

// TestTaskENIAckWithinTimeout tests the eni state change was reported before the timeout, for a regular eni
func TestTaskENIAckWithinTimeout(t *testing.T) {
	testENIAckWithinTimeout(t, apieni.ENIAttachmentTypeENI)
}

// TestTaskENIAckWithinTimeout tests the eni state change was reported before the timeout, for a trunk eni
func TestTrunkENIAckWithinTimeout(t *testing.T) {
	testENIAckWithinTimeout(t, apieni.ENIAttachmentTypeTrunkENI)
}

func testENIAckWithinTimeout(t *testing.T, attachmentType string) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	taskEngineState := dockerstate.NewTaskEngineState()
	expiresAt := time.Now().Add(time.Duration(waitTimeoutMillis) * time.Millisecond)
	err := addENIAttachmentToState(attachmentType, attachmentArn, taskArn, randomMAC, expiresAt, taskEngineState)
	assert.NoError(t, err)
	assert.Len(t, taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments(), 1)
	eniAttachment, ok := taskEngineState.(*dockerstate.DockerTaskEngineState).ENIByMac(randomMAC)
	assert.True(t, ok)
	eniAttachment.SetSentStatus()

	time.Sleep(time.Millisecond * waitTimeoutMillis)

	assert.Len(t, taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments(), 1)
}

// TestHandleENIAttachmentTaskENI tests handling a new task eni
func TestHandleENIAttachmentTaskENI(t *testing.T) {
	testHandleENIAttachment(t, apieni.ENIAttachmentTypeENI)
}

// TestHandleENIAttachmentTaskENI tests handling a new trunk eni
func TestHandleENIAttachmentTrunkENI(t *testing.T) {
	testHandleENIAttachment(t, apieni.ENIAttachmentTypeTrunkENI)
}

func testHandleENIAttachment(t *testing.T, attachmentType string) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	taskEngineState := dockerstate.NewTaskEngineState()
	expiresAt := time.Now().Add(time.Duration(waitTimeoutMillis) * time.Millisecond)
	stateManager := statemanager.NewNoopStateManager()
	err := handleENIAttachment(attachmentType, attachmentArn, taskArn, randomMAC, expiresAt, taskEngineState, stateManager)
	assert.NoError(t, err)
	assert.Len(t, taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments(), 1)
	eniAttachment, ok := taskEngineState.(*dockerstate.DockerTaskEngineState).ENIByMac(randomMAC)
	assert.True(t, ok)
	eniAttachment.SetSentStatus()

	time.Sleep(time.Millisecond * waitTimeoutMillis)

	assert.Len(t, taskEngineState.(*dockerstate.DockerTaskEngineState).AllENIAttachments(), 1)
}