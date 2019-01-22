package handler

import (
	"testing"
	"time"

	apieni "github.com/aws/amazon-ecs-agent/agent/api/eni"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
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
