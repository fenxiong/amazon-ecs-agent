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
	"fmt"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/acs/model/ecsacs"
	apieni "github.com/aws/amazon-ecs-agent/agent/api/eni"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/aws/amazon-ecs-agent/agent/wsclient"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/amazon-ecs-agent/agent/statemanager"

	"github.com/cihub/seelog"
	"github.com/pkg/errors"
)

// ackTimeoutHandler remove ENI attachment from agent state after the ENI ack timeout
type ackTimeoutHandler struct {
	mac   string
	state dockerstate.TaskEngineState
}

func (handler *ackTimeoutHandler) handle() {
	eniAttachment, ok := handler.state.ENIByMac(handler.mac)
	if !ok {
		seelog.Warnf("Timed out waiting for ENI ack; ignoring unmanaged ENI attachment with MAC address: %s", handler.mac)
		return
	}
	if !eniAttachment.IsSent() {
		seelog.Infof("Timed out waiting for ENI ack; removing ENI attachment record with MAC address: %s", handler.mac)
		handler.state.RemoveENIAttachment(handler.mac)
	}
}

// sendAck sends ack for a certain ACS message
func sendAck(acsClient wsclient.ClientServer, clusterArn *string, containerInstanceArn *string, messageId *string) {
	if err := acsClient.MakeRequest(&ecsacs.AckRequest{
		Cluster:           clusterArn,
		ContainerInstance: containerInstanceArn,
		MessageId:         messageId,
	}); err != nil {
		seelog.Warnf("Failed to ack request with messageId: %s, error: %v", aws.StringValue(messageId), err)
	}
}

// handlerENIAttachment handles an ENI attachment via the following:
// 1. Checks whether we already have this attachment in state, if so, start its ack timer and return
// 2. Otherwise adds the attachment to state, starts its ack timer, and saves the state
func handleENIAttachment(attachmentType, attachmentARN, taskARN, mac string, expiresAt time.Time, state dockerstate.TaskEngineState, saver statemanager.Saver) error {
	// Check if this is a duplicate attachment
	if eniAttachment, ok := state.ENIByMac(mac); ok {
		seelog.Infof("Duplicate %s attachment message for ENI with MAC address: %s", attachmentType, mac)
		eniAckTimeoutHandler := ackTimeoutHandler{mac: mac, state: state}
		return eniAttachment.StartTimer(eniAckTimeoutHandler.handle)
	}
	if err := addENIAttachmentToState(attachmentType, attachmentARN, taskARN, mac, expiresAt, state); err != nil {
		return errors.Wrapf(err, fmt.Sprintf("attach %s message handler: unable to add eni attachment to engine state", attachmentType))
	}
	if err := saver.Save(); err != nil {
		return errors.Wrapf(err, fmt.Sprintf("attach %s message handler: unable to save agent state", attachmentType))
	}
	return nil
}

// addENIAttachmentToState adds an ENI attachment to state, and start its ack timer
func addENIAttachmentToState(attachmentType, attachmentARN, taskARN, mac string, expiresAt time.Time, state dockerstate.TaskEngineState) error {
	eniAttachment := &apieni.ENIAttachment{
		TaskARN:          taskARN,
		AttachmentType:   attachmentType,
		AttachmentARN:    attachmentARN,
		AttachStatusSent: false,
		MACAddress:       mac,
		ExpiresAt:        expiresAt, // Stop tracking the eni attachment after timeout
	}
	eniAckTimeoutHandler := ackTimeoutHandler{mac: mac, state: state}
	if err := eniAttachment.StartTimer(eniAckTimeoutHandler.handle); err != nil {
		return err
	}

	if attachmentType == apieni.ENIAttachmentTypeENI {
		seelog.Infof("Adding eni attachment info for task '%s' to state, attachment=%s mac=%s",
			taskARN, attachmentARN, mac)
	} else if attachmentType == apieni.ENIAttachmentTypeTrunkENI {
		seelog.Infof("Adding trunk eni attachment info to state, attachment=%s mac=%s", attachmentARN, mac)
	}
	state.AddENIAttachment(eniAttachment)
	return nil
}
