// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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
	"context"
	"encoding/json"

	"github.com/aws/amazon-ecs-agent/agent/acs/model/ecsacs"
	"github.com/aws/amazon-ecs-agent/agent/wsclient"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/cihub/seelog"
)

type dynamicConfigHandler struct {
	cluster                       string
	containerInstanceArn          string
	dynamicConfigMessageBuffer    chan *ecsacs.DynamicConfigMessage
	dynamicConfigAckMessageBuffer chan string
	ctx                           context.Context
	cancel                        context.CancelFunc
	acsClient                     wsclient.ClientServer
}

// newDynamicConfigHandler returns an instance of the dynamicConfigHandler struct.
func newDynamicConfigHandler(cluster, containerInstanceArn string, ctx context.Context,
	acsClient wsclient.ClientServer) dynamicConfigHandler {

	// Create a cancelable context from the parent context
	derivedContext, cancel := context.WithCancel(ctx)
	return dynamicConfigHandler{
		cluster:                       cluster,
		containerInstanceArn:          containerInstanceArn,
		dynamicConfigMessageBuffer:    make(chan *ecsacs.DynamicConfigMessage),
		dynamicConfigAckMessageBuffer: make(chan string),
		ctx:                           derivedContext,
		cancel:                        cancel,
		acsClient:                     acsClient,
	}
}

// handlerFunc returns a function to enqueue requests onto the buffer
func (dynamicConfigHandler *dynamicConfigHandler) handlerFunc() func(message *ecsacs.DynamicConfigMessage) {
	return func(message *ecsacs.DynamicConfigMessage) {
		dynamicConfigHandler.dynamicConfigMessageBuffer <- message
	}
}

// start() invokes go routines to handle receive and respond to heartbeats
func (dynamicConfigHandler *dynamicConfigHandler) start() {
	go dynamicConfigHandler.handleDynamicConfigMessage()
	go dynamicConfigHandler.sendDynamicConfigMessageAck()
}

func (dynamicConfigHandler *dynamicConfigHandler) handleDynamicConfigMessage() {
	for {
		select {
		case message := <-dynamicConfigHandler.dynamicConfigMessageBuffer:
			if err := dynamicConfigHandler.handleSingleDynamicConfigMessage(message); err != nil {
				seelog.Warnf("Unable to handle dynamic config message [%s]: %s", message.String(), err)
			}
		case <-dynamicConfigHandler.ctx.Done():
			return
		}
	}
}

func (dynamicConfigHandler *dynamicConfigHandler) handleSingleDynamicConfigMessage(message *ecsacs.DynamicConfigMessage) error {
	logMessage(message)
	go func() {
		dynamicConfigHandler.dynamicConfigAckMessageBuffer <- aws.StringValue(message.MessageId)
	}()
	return nil
}

// logMessage logs the message for testing purpose.
func logMessage(message *ecsacs.DynamicConfigMessage) {
	msgID := aws.StringValue(message.MessageId)
	seelog.Infof("Got dynamic config message with id: %s", msgID)

	b, err := json.Marshal(message)
	if err != nil {
		seelog.Errorf("Error marshalling dynamic config message [%s]: %v", msgID, err)
		return
	}
	seelog.Infof("Dynamic config message [%s] content: %s", msgID, string(b))
}

func (dynamicConfigHandler *dynamicConfigHandler) sendDynamicConfigMessageAck() {
	for {
		select {
		case msgID := <-dynamicConfigHandler.dynamicConfigAckMessageBuffer:
			dynamicConfigHandler.sendSingleDynamicConfigAck(msgID)
		case <-dynamicConfigHandler.ctx.Done():
			return
		}
	}
}

func (dynamicConfigHandler *dynamicConfigHandler) sendSingleDynamicConfigAck(msgID string) {
	seelog.Infof("Acking dynamic config message id: %s", msgID)
	err := dynamicConfigHandler.acsClient.MakeRequest(&ecsacs.AckRequest{
		Cluster:           aws.String(dynamicConfigHandler.cluster),
		ContainerInstance: aws.String(dynamicConfigHandler.containerInstanceArn),
		MessageId:         aws.String(msgID),
	})
	if err != nil {
		seelog.Warnf("Error acking dynamic config message [%s]: %v", msgID, err)
	}
}

func (dynamicConfigHandler *dynamicConfigHandler) stop() {
	dynamicConfigHandler.cancel()
}

func (dynamicConfigHandler *dynamicConfigHandler) clearAcks() {
	for {
		select {
		case <-dynamicConfigHandler.dynamicConfigAckMessageBuffer:
		default:
			return
		}
	}
}
