// Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"time"

	"github.com/aws/amazon-ecs-agent/agent/acs/model/ecsacs"
	apieni "github.com/aws/amazon-ecs-agent/agent/api/eni"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/aws/amazon-ecs-agent/agent/statemanager"
	"github.com/aws/amazon-ecs-agent/agent/wsclient"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/cihub/seelog"
	"github.com/pkg/errors"

	"context"
)

// attachENIHandler handles task ENI attach operation for the ACS client
type attachENIHandler struct {
	messageBuffer     chan *ecsacs.AttachTaskNetworkInterfacesMessage
	ctx               context.Context
	cancel            context.CancelFunc
	saver             statemanager.Saver
	cluster           *string
	containerInstance *string
	acsClient         wsclient.ClientServer
	state             dockerstate.TaskEngineState
}

// newAttachENIHandler returns an instance of the attachENIHandler struct
func newAttachENIHandler(ctx context.Context,
	cluster string,
	containerInstanceArn string,
	acsClient wsclient.ClientServer,
	taskEngineState dockerstate.TaskEngineState,
	saver statemanager.Saver) attachENIHandler {

	// Create a cancelable context from the parent context
	derivedContext, cancel := context.WithCancel(ctx)
	return attachENIHandler{
		messageBuffer:     make(chan *ecsacs.AttachTaskNetworkInterfacesMessage),
		ctx:               derivedContext,
		cancel:            cancel,
		cluster:           aws.String(cluster),
		containerInstance: aws.String(containerInstanceArn),
		acsClient:         acsClient,
		state:             taskEngineState,
		saver:             saver,
	}
}

// handlerFunc returns a function to enqueue requests onto attachENIHandler buffer
func (attachENIHandler *attachENIHandler) handlerFunc() func(message *ecsacs.AttachTaskNetworkInterfacesMessage) {
	return func(message *ecsacs.AttachTaskNetworkInterfacesMessage) {
		attachENIHandler.messageBuffer <- message
	}
}

// start invokes handleMessages to ack each enqueued request
func (attachENIHandler *attachENIHandler) start() {
	go attachENIHandler.handleMessages()
}

// stop is used to invoke a cancellation function
func (attachENIHandler *attachENIHandler) stop() {
	attachENIHandler.cancel()
}

// handleMessages handles each message one at a time
func (attachENIHandler *attachENIHandler) handleMessages() {
	for {
		select {
		case message := <-attachENIHandler.messageBuffer:
			if err := attachENIHandler.handleSingleMessage(message); err != nil {
				seelog.Warnf("Unable to handle ENI Attachment message [%s]: %v", message.String(), err)
			}
		case <-attachENIHandler.ctx.Done():
			return
		}
	}
}

// handleSingleMessage acks the message received
func (handler *attachENIHandler) handleSingleMessage(message *ecsacs.AttachTaskNetworkInterfacesMessage) error {
	receivedAt := time.Now()
	// Validate fields in the message
	if err := validateAttachTaskNetworkInterfacesMessage(message); err != nil {
		return errors.Wrapf(err,
			"attach eni message handler: error validating AttachTaskNetworkInterface message received from ECS")
	}

	// Send ACK
	go sendAck(handler.acsClient, message.ClusterArn, message.ContainerInstanceArn, message.MessageId)

	// Handle the attachment
	attachmentARN := aws.StringValue(message.ElasticNetworkInterfaces[0].AttachmentArn)
	taskARN := aws.StringValue(message.TaskArn)
	mac := aws.StringValue(message.ElasticNetworkInterfaces[0].MacAddress)
	expiresAt := receivedAt.Add(time.Duration(aws.Int64Value(message.WaitTimeoutMs)) * time.Millisecond)
	return handleENIAttachment(apieni.ENIAttachmentTypeENI, attachmentARN, taskARN, mac, expiresAt, handler.state, handler.saver)
}

// validateAttachTaskNetworkInterfacesMessage performs validation checks on the
// AttachTaskNetworkInterfacesMessage
func validateAttachTaskNetworkInterfacesMessage(message *ecsacs.AttachTaskNetworkInterfacesMessage) error {
	if message == nil {
		return errors.Errorf("attach eni handler validation: empty AttachTaskNetworkInterface message received from ECS")
	}

	messageId := aws.StringValue(message.MessageId)
	if messageId == "" {
		return errors.Errorf("attach eni handler validation: message id not set in AttachTaskNetworkInterface message received from ECS")
	}

	clusterArn := aws.StringValue(message.ClusterArn)
	if clusterArn == "" {
		return errors.Errorf("attach eni handler validation: clusterArn not set in AttachTaskNetworkInterface message received from ECS")
	}

	containerInstanceArn := aws.StringValue(message.ContainerInstanceArn)
	if containerInstanceArn == "" {
		return errors.Errorf("attach eni handler validation: containerInstanceArn not set in AttachTaskNetworkInterface message received from ECS")
	}

	enis := message.ElasticNetworkInterfaces
	if len(enis) != 1 {
		return errors.Errorf("attach eni handler validation: incorrect number of ENIs in AttachTaskNetworkInterface message received from ECS. Obtained %d", len(enis))
	}

	eni := enis[0]
	if aws.StringValue(eni.MacAddress) == "" {
		return errors.Errorf("attach eni handler validation: MACAddress not listed in AttachTaskNetworkInterface message received from ECS")
	}

	taskArn := aws.StringValue(message.TaskArn)
	if taskArn == "" {
		return errors.Errorf("attach eni handler validation: taskArn not set in AttachTaskNetworkInterface message received from ECS")
	}

	timeout := aws.Int64Value(message.WaitTimeoutMs)
	if timeout <= 0 {
		return errors.Errorf("attach eni handler validation: invalid timeout listed in AttachTaskNetworkInterface message received from ECS")

	}

	return nil
}
