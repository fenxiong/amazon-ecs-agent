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

package eventhandler

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/amazon-ecs-agent/agent/api"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/aws/amazon-ecs-agent/agent/statechange"
	"github.com/aws/amazon-ecs-agent/agent/statemanager"
	"github.com/aws/amazon-ecs-agent/agent/utils/retry"
	"github.com/cihub/seelog"
)

// AttachmentHandler is a handler that is responsible for submitting attachment state change events
// to backend
type AttachmentHandler struct {
	// stateSaver is a statemanager which may be used to save any
	// changes to an attachment's SentStatus
	stateSaver statemanager.Saver

	// attachmentLock is a map from attachment ARN to a lock.
	// we need to have a lock for each attachment so that the attached
	// status of an attachment won't be sent multiple times
	attachmentLock map[string]*sync.Mutex

	// lock is used to safely access the attachmentLock map
	lock sync.Mutex

	state  dockerstate.TaskEngineState
	client api.ECSClient
	ctx    context.Context
}

// NewAttachmentHandler returns a new AttachmentHandler object
func NewAttachmentHandler(ctx context.Context,
	stateSaver statemanager.Saver,
	state dockerstate.TaskEngineState,
	client api.ECSClient) *AttachmentHandler {
	return &AttachmentHandler{
		ctx:            ctx,
		stateSaver:     stateSaver,
		state:          state,
		client:         client,
		attachmentLock: make(map[string]*sync.Mutex),
	}
}

// AddStateChangeEvent adds a state change event to AttachmentHandler for it to handle
func (handler *AttachmentHandler) AddStateChangeEvent(change statechange.Event) error {
	if change.GetEventType() != statechange.AttachmentEvent {
		return errors.New(fmt.Sprintf("eventhandler: attachment handler received unrecognized event type: %d", change.GetEventType()))
	}
	event, ok := change.(api.AttachmentStateChange)
	if !ok {
		return errors.New("eventhandler: unable to get attachment event from state change event")
	}

	go handler.submitAttachmentEvent(&event)
	return nil
}

// submitAttachmentEvent submits an attachment state change to backend
func (handler *AttachmentHandler) submitAttachmentEvent(attachmentChange *api.AttachmentStateChange) {
	attachmentARN := attachmentChange.Attachment.AttachmentARN

	var atmLock *sync.Mutex // the lock for the attachment
	handler.lock.Lock()
	if _, ok := handler.attachmentLock[attachmentARN]; !ok {
		atmLock = new(sync.Mutex)
		handler.attachmentLock[attachmentARN] = atmLock
	} else {
		atmLock = handler.attachmentLock[attachmentARN]
	}
	handler.lock.Unlock()

	// holds the lock for the attachment to be sent before sending the change
	seelog.Debugf("AttachmentHandler: acquiring attachment lock before sending attachment state change for attachment %s", attachmentARN)
	atmLock.Lock()
	seelog.Debugf("AttachmentHandler: acquired attachment lock for attachment %s", attachmentARN)
	defer atmLock.Unlock()

	backoff := GetSubmitAttachmentStateBackoffFunc()

	retry.RetryWithBackoffCtx(handler.ctx, backoff, func() error {
		if !attachmentChangeShouldBeSent(attachmentChange) {
			seelog.Debugf("AttachmentHandler: not sending attachment state change [%s] as it should not be sent", attachmentChange.String())
			// if the attachment state change should not be sent, we don't need to retry anymore so return nil here
			return nil
		}

		seelog.Infof("AttachmentHandler: sending attachment state change: %s", attachmentChange.String())
		if err := handler.client.SubmitAttachmentStateChange(*attachmentChange); err != nil {
			seelog.Errorf("AttachmentHandler: error submitting attachment state change [%s]: %v", attachmentChange.String(), err)
			return err
		}

		attachmentChange.Attachment.SetSentStatus()
		attachmentChange.Attachment.StopAckTimer()
		handler.stateSaver.Save()
		seelog.Debugf("AttachmentHandler: submitted attachment state change: %s", attachmentChange.String())
		return nil
	})
}

// attachmentChangeShouldBeSent checks whether an attachment state change should be sent to backend
func attachmentChangeShouldBeSent(attachmentChange *api.AttachmentStateChange) bool {
	return !attachmentChange.Attachment.HasExpired() && !attachmentChange.Attachment.IsSent()
}

// GetSubmitAttachmentStateBackoffFunc is a func that returns a backoff object;
// this is made as a function object so that we can use smaller backoff in unit test
var GetSubmitAttachmentStateBackoffFunc = GetSubmitAttachmentStateBackoff

// GetSubmitAttachmentStateBackoff returns a backoff object used in submitting attachment state change
func GetSubmitAttachmentStateBackoff() retry.Backoff {
	return retry.NewExponentialBackoff(submitStateBackoffMin, submitStateBackoffMax,
		submitStateBackoffJitterMultiple, submitStateBackoffMultiple)
}
