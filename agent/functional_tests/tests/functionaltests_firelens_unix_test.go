// +build !windows,functional

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

package functional_tests

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/ec2"
	. "github.com/aws/amazon-ecs-agent/agent/functional_tests/util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	getLogSenderMessageFuncFluentd = func(taskID string, t *testing.T) string {
		cwlClient := cloudwatchlogs.New(session.New(), aws.NewConfig().WithRegion(*ECS.Config.Region))
		params := &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName:  aws.String(awslogsLogGroupName),
			LogStreamNames: aws.StringSlice([]string{fmt.Sprintf("firelens-fluentd/firelens/%s", taskID)}),
			// The firelens container's stdout contains both log sender's log and its own logs.
			// Filter out the logs that belong to the firelens container itself.
			// FilterPattern: aws.String(`-"[info]"`),
			FilterPattern: aws.String(`?"\"log\":\"pass\"" ?"\"log\":\"filtered\""`),
		}

		resp, err := waitCloudwatchLogsWithFilter(cwlClient, params, 30 * time.Second)
		require.NoError(t, err, "CloudWatchLogs get log failed")

		// Expect one message sent from the log sender.
		assert.Equal(t, 1, len(resp.Events))
		line := aws.StringValue(resp.Events[0].Message)

		// Format of the log should be something like:
		// Timestamp containerName-taskID: {"source":"stdout","log":"...","container_id":"...","container_name":"...","ec2_instance_id":"...","ecs_cluster":"...","ecs_task_arn":"...","ecs_task_definition":"..."}
		// Return the last part which will be checked by the caller (testFirelens).
		fields := strings.Split(line, " ")
		message := fields[len(fields)-1]

		return message
	}

	getLogSenderMessageFuncFluentbit = func(taskID string, t *testing.T) string {
		cwlClient := cloudwatchlogs.New(session.New(), aws.NewConfig().WithRegion(*ECS.Config.Region))
		params := &cloudwatchlogs.GetLogEventsInput{
			LogGroupName:  aws.String(awslogsLogGroupName),
			LogStreamName: aws.String(fmt.Sprintf("firelens-fluentbit-logsender-%s", taskID)),
		}

		// Expect one message sent from the log sender.
		resp, err := waitCloudwatchLogs(cwlClient, params)
		require.NoError(t, err)
		assert.Equal(t, 1, len(resp.Events))
		message := aws.StringValue(resp.Events[0].Message)
		return message
	}
)

// TestFirelensFluentd starts a task that has a log sender container and a firelens container with configuration type
// as fluentd. The log sender container is configured to send logs via the firelens container. It echoes something
// and then exits. The firelens container is configured to route the logs from the log sender container to its stdout.
// The firelens container itself is configured to use the awslogs logging driver, so that we can examine its stdout
// by querying cloudwatch logs.
// Since the test is similar to TestFirelensFluentbit, the common parts of the two tests are extracted to a helper method
// testFirelens, while the different parts are covered in getLogSenderMessageFunc.
func TestFirelensFluentd(t *testing.T) {
	// getLogSenderMessageFunc defines a function that specifies how to find the log sender's logs after the task
	// finished running.
	getLogSenderMessageFunc := getLogSenderMessageFuncFluentd

	testFirelens(t, "fluentd", getLogSenderMessageFunc)
}

// TestFirelensFluentbit starts a task that has a log sender container and a firelens container with configuration type
// as fluentbit. The log sender container is configured to send logs via the firelens container. It echoes something
// and then exits. The firelens container is configured to route the logs from the log sender container directly to
// cloudwatch logs (with a fluentbit cloudwatch plugin that's available in the amazon/aws-for-fluent-bit container image).
func TestFirelensFluentbit(t *testing.T) {
	// getLogSenderMessageFunc defines a function that specifies how to find the log sender's logs after the task
	// finished running.
	getLogSenderMessageFunc := getLogSenderMessageFuncFluentbit

	testFirelens(t, "fluentbit", getLogSenderMessageFunc)
}

func TestFirelensFluentdOld(t *testing.T)  {
	// getLogSenderMessageFunc defines a function that specifies how to find the log sender's logs after the task
	// finished running.
	getLogSenderMessageFunc := getLogSenderMessageFuncFluentd

	testFirelens(t, "fluentd-old", getLogSenderMessageFunc)
}

func TestFirelensFluentdNoDep(t *testing.T)  {
	// getLogSenderMessageFunc defines a function that specifies how to find the log sender's logs after the task
	// finished running.
	getLogSenderMessageFunc := getLogSenderMessageFuncFluentd

	testFirelens(t, "fluentd-no-dep", getLogSenderMessageFunc)
}

func testFirelens(t *testing.T, firelensConfigType string, getLogSenderMessageFunc func(string, *testing.T)string) {
	iid, _ := ec2.NewEC2MetadataClient(nil).InstanceIdentityDocument()
	instanceID := iid.InstanceID

	agentOptions := &AgentOptions{
		ExtraEnvironment: map[string]string{
			"ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION": "1m",
			"ECS_AVAILABLE_LOGGING_DRIVERS": `["awslogs"]`,
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")
	agent := RunAgent(t, agentOptions)
	defer agent.Cleanup()

	// TODO: change to 1.30.0 when merging the changes.
	agent.RequireVersion(">=1.28.1")

	tdOverrides := make(map[string]string)

	testTask, err := agent.StartTaskWithTaskDefinitionOverrides(t, "firelens-"+firelensConfigType, tdOverrides)
	require.NoError(t, err)

	err = testTask.WaitStopped(waitTaskStateChangeDuration)
	require.NoError(t, err)

	taskID, err := GetTaskID(aws.StringValue(testTask.TaskArn))
	require.NoError(t, err)
	message := getLogSenderMessageFunc(taskID, t)

	// Message should be like: {"source":"stdout","log":"...","container_id":"...","container_name":"...","ec2_instance_id":"...","ecs_cluster":"...","ecs_task_arn":"...","ecs_task_definition":"..."}.
	// Verify each of the field.
	jsonBlob := make(map[string]string)
	err = json.Unmarshal([]byte(message), &jsonBlob)
	require.NoError(t, err)

	assert.Equal(t, "stdout", jsonBlob["source"])
	assert.Equal(t, "pass", jsonBlob["log"])
	assert.Contains(t, jsonBlob, "container_id")
	assert.Contains(t, jsonBlob["container_name"], "logsender")
	assert.Equal(t, instanceID, jsonBlob["ec2_instance_id"])
	assert.Equal(t, agent.Cluster, jsonBlob["ecs_cluster"])
	assert.Equal(t, *testTask.TaskArn, jsonBlob["ecs_task_arn"])
	assert.Contains(t, *testTask.TaskDefinitionArn, jsonBlob["ecs_task_definition"])
}

