// +build !windows,functional

// Copyright 2014-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/ec2"
	ecsapi "github.com/aws/amazon-ecs-agent/agent/ecs_client/model/ecs"
	. "github.com/aws/amazon-ecs-agent/agent/functional_tests/util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enableAccountSetting(settingName string, t *testing.T) {
	putAccountSettingInput := ecsapi.PutAccountSettingInput{
		Name:  aws.String(settingName),
		Value: aws.String("enabled"),
	}
	_, err := ECS.PutAccountSetting(&putAccountSettingInput)
	require.NoError(t, err)
}

func TestInstanceHappyCase(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// Wait for container instance to become active
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// Expect one more interface to be attached (i.e. the Trunk)
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)
}

func TestTaskHappyCase(t *testing.T) {
	// launch agent

	// wait for container instance to reach ACTIVE

	// check ENI attached

	// start task, wait stop, check exit code

	// stop agent, deregister container instance

	// check ENI detached
}

func TestTrunkingDisableViaAgentConfig(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	// launch agent with ENI trunking disabled
	agentOptions := &AgentOptions{
		EnableTaskENI: true,
		ExtraEnvironment: map[string]string{
			"ECS_ENABLE_HIGH_DENSITY_ENI": "false",
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	agent := RunAgent(t, agentOptions)
	defer agent.Cleanup()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)

	// verify no ENI is attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount, interfaceCount)
}

func TestAgentRestartsWithDataFile(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	// launch agent
	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// stop agent
	t.Log("Stopping the Agent")
	agent.StopAgent()

	// start agent
	t.Log("Starting the Agent again")
	agent.StartAgent()

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI still attached
	interfaceCount, err = GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)
}

// Instead of removing the data file of the previous agent and then starts another agent,
// this test just "run" another agent with RunAgent because that will start another test agent
// using another temp directory which won't have the data file of the previous agent
func TestAgentRestartsWithoutDataFile(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent 1
	t.Log("Launching Agent 1")
	agent1 := RunAgent(t, agentOptions)
	defer func() {
		t.Log("Cleanup Agent 1")
		agent1.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent1.Cluster,
			ContainerInstance: &agent1.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent1.TestCleanup()
	}()
	t.Logf("Agent 1's container instance arn: %s", agent1.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent1.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// stop agent
	t.Log("Stopping Agent 1")
	agent1.StopAgent()

	// run another agent
	t.Log("Launching Agent 2")
	agent2 := RunAgent(t, agentOptions)
	defer func() {
		t.Log("Cleanup Agent 2")
		agent2.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent2.Cluster,
			ContainerInstance: &agent2.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached;
		// Agent 2 is cleaned up first so expecting existingInterfaceCount + 1 ENI count
		err = WaitNetworkInterfaceCount(existingInterfaceCount + 1, 1 * time.Minute)
		assert.NoError(t, err)

		agent2.TestCleanup()
	}()
	t.Logf("Agent 2's container instance arn: %s", agent2.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent2.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check another ENI attached
	interfaceCount, err = GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 2, interfaceCount)
}

func TestTrunkProvisioningEdgeCase3(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// stop agent
	agent.StopAgent()

	// launch agent again with ENI trunking disabled
	if agent.Options.ExtraEnvironment == nil  {
		agent.Options.ExtraEnvironment = make(map[string]string)
	}
	agent.Options.ExtraEnvironment["ECS_ENABLE_HIGH_DENSITY_ENI"] = "false"
	agent.StartAgent()

	// wait for container instance to reach ACTIVE again
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)
}

func TestTrunkENILimit(t *testing.T) {
	t.Skip("TBD: why is this broken")

	// only run on certain instance type
	RequireInstanceTypes(t, []string{"c5", "m5", "a1"})
	iid, _ := ec2.NewEC2MetadataClient(nil).InstanceIdentityDocument()
	instanceType := iid.InstanceType
	if !strings.HasSuffix(instanceType, "2xlarge") {
		t.Skipf("Skipping the test for instance type %s", instanceType)
	}

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	if existingInterfaceCount != 1 {
		t.Skipf("Skipping the test when current ENI count is not 1. Current ENI count: %d", existingInterfaceCount)
	}

	// manually attach 3 ENIs to the instance to reach maximum limit)
	ec2Client := GetEC2Client(iid.Region)
	subnetID, err := GetSubnetID()
	require.NoError(t, err)
	instanceID := iid.InstanceID

	// verify ENI are all detached at the end
	defer func() {
		err = WaitNetworkInterfaceCount(1, 1 * time.Minute)
		assert.NoError(t, err)
	}()

	for i := 0; i < 3; i++ {
		networkInterfaceID, err := CreateNetworkInterface(ec2Client, subnetID)
		require.NoError(t, err)
		t.Logf("Created network interface: %s", networkInterfaceID)

		attachmentID, err := AttachNetworkInterface(ec2Client, instanceID, networkInterfaceID, int64(i + 1))
		require.NoError(t, err)
		t.Logf("Attached network interface %s, attachmentID: %s", networkInterfaceID, attachmentID)

		defer func() {
			err := DetachNetworkInterface(ec2Client, attachmentID)
			if err != nil {
				t.Logf("Error detaching attachment %s: %v", attachmentID, err)
			} else {
				t.Logf("Detached attachment %s", attachmentID)
			}

			// wait until detached
			err = WaitNetworkInterfaceAvailable(ec2Client, networkInterfaceID, 1 * time.Minute)
			assert.NoError(t, err)

			err = DeleteNetworkInterface(ec2Client, networkInterfaceID)
			if err != nil {
				t.Logf("Error deleting network interface %s: %v", networkInterfaceID, err)
			} else {
				t.Logf("Deleted network interface %s", networkInterfaceID)
			}
		}()
	}

	// launch agent
	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)

	// verify container instance ends up with REGISTRATION_FAILED status
	err = agent.WaitContainerInstanceStatus("REGISTRATION_FAILED", 10 * time.Minute)
	assert.NoError(t, err)

	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait until maximum ENI attached
	err = WaitNetworkInterfaceCount(4, 1 * time.Minute)
	assert.NoError(t, err)
}

func TestTrunkENITagging(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)
	enableAccountSetting("containerInstanceLongArnFormat", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
		ExtraEnvironment: map[string]string{
			"ECS_CONTAINER_INSTANCE_TAGS": `{"key1": "value1", "key2": "value2"}`,
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// check ENI tags
	expectedKeys := []string{"key1", "key2"}
	ec2Client := GetEC2Client("")
	tagDescriptions, err := GetResourcesWithTagKeys(ec2Client, expectedKeys)
	require.NoError(t, err)

	// rough check - just check that there's an ENI that's tagged with key1, and also one that's tagged with key2
	var b1, b2 bool
	for _, tagDescription := range tagDescriptions {
		if aws.StringValue(tagDescription.ResourceType) != "network-interface" {
			continue
		}

		if aws.StringValue(tagDescription.Key) == "key1" && aws.StringValue(tagDescription.Value) == "value1" {
			b1 = true
		}

		if aws.StringValue(tagDescription.Key) == "key2" && aws.StringValue(tagDescription.Value) == "value2" {
			b2 = true
		}
	}

	assert.True(t, b1 && b2, fmt.Sprintf("Unsatisfied tag descriptions: %v", tagDescriptions))
}

func TestTaskSecurityGroup(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// create a security group without opening port 80
	ec2Client := GetEC2Client("")
	vpcID, err := GetVPCID()
	require.NoError(t, err)
	groupID, err := CreateSecurityGroup(ec2Client, "eni-trunking-manual-test",
		"Security group created for eni trunking manual test", vpcID)
	defer func(){
		err := DeleteSecurityGroup(ec2Client, groupID)
		assert.NoError(t, err)
	}()

	// start task with that security group
	task, err := agent.StartAWSVPCTaskWithSecurityGroup("awsvpc-trunking-nginx", groupID, nil)
	assert.NoError(t, err)
	defer func() {
		if err := task.Stop(); err != nil {
			return
		}
		task.WaitStopped(1 * time.Minute)
	}()

	// Wait for task to be running
	err = task.WaitRunning(1 * time.Minute)
	assert.NoError(t, err)

	// try visiting http://(PRIVATE_IP)
	taskPrivateIP, err := GetTaskPrivateIP(task.Task)
	require.NoError(t, err)
	fmt.Printf("Got task private ip: %s", taskPrivateIP)

	endpoint := fmt.Sprintf("http://%s", taskPrivateIP)

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	fmt.Printf("Try accessing %s...\n", endpoint)
	err = WaitEndpointAvailable(client, endpoint, 10 * time.Second)
	assert.Error(t, err)

	// update security group rule to open port 80
	err = AuthorizeSecurityGroupIngress(ec2Client, groupID, "tcp", "0.0.0.0/0", 80, 80)
	require.NoError(t, err)

	// try visiting http://(PRIVATE_IP) again
	fmt.Printf("Try accessing %s again...\n", endpoint)
	err = WaitEndpointAvailable(client, endpoint, 10 * time.Second)
	assert.NoError(t, err)
}

func TestBlockIMDS(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
		ExtraEnvironment: map[string]string{
			"ECS_AWSVPC_BLOCK_IMDS": "true",
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent with IMDS blocked
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// start task, wait task stop, check exit code
	task, err := agent.StartAWSVPCTask("awsvpc-trunking-imds", nil)
	require.NoError(t, err)

	err = task.WaitStopped(1 * time.Minute)
	require.NoError(t, err)
	if exit, ok := task.ContainerExitcode("exit"); !ok || exit != 0 {
		t.Errorf("Expected exit to exit with 0; actually exited (%v) with %v", ok, exit)
	}

	// cleanup
	defer agent.SweepTask(task)
}

func TestBranchENILimit(t *testing.T) {
	t.Skip("TBD: control plane currently having dummy limit for branches")
	// only run on certain instance type

	// launch agent

	// wait for container instance to reach ACTIVE

	// start multiple tasks until limit

	// wait tasks stop, check exit code

	// cleanup
}

func TestInterContainerCommunication(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// start task, wait task stop, check exit code
	task, err := agent.StartAWSVPCTask("awsvpc-trunking-inter", nil)
	require.NoError(t, err)

	err = task.WaitStopped(1 * time.Minute)
	assert.NoError(t, err)
	if exit, ok := task.ContainerExitcode("container_1"); !ok || exit != 0 {
		t.Errorf("Expected exit to exit with 0; actually exited (%v) with %v", ok, exit)
	}

	// cleanup
	defer agent.SweepTask(task)
}

func TestPluginLogging(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)
	enableAccountSetting("taskLongArnFormat", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
		ExtraEnvironment: map[string]string{
			"ECS_CONTAINER_STOP_TIMEOUT": "10s",
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// start task
	task, err := agent.StartAWSVPCTask("awsvpc-trunking-sleep-long", nil)
	require.NoError(t, err)
	defer func() {
		if err := task.Stop(); err != nil {
			return
		}
		task.WaitStopped(1 * time.Minute)
	}()

	// Wait for task to be running
	err = task.WaitRunning(1 * time.Minute)
	assert.NoError(t, err)

	// check log file
	now := time.Now()
	suffix := fmt.Sprintf("%04d-%02d-%02d-%02d", now.Year(), now.Month(), now.Day(), now.Hour())
	logFileName := "vpc-branch-eni.log." + suffix

	branchLogFilePath := filepath.Join(agent.TestDir, "log", logFileName)
	content, err := ioutil.ReadFile(branchLogFilePath)
	assert.NoError(t, err)

	contentStr := string(content)
	assert.True(t, strings.Contains(contentStr, "[DEBUG]"))
}

func TestBranchENITagging(t *testing.T) {
	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)
	enableAccountSetting("taskLongArnFormat", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
		ExtraEnvironment: map[string]string{
			"ECS_CONTAINER_STOP_TIMEOUT": "10s",
		},
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	t.Log("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	t.Logf("Container instance arn: %s", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// start task, wait task stop, check exit code
	task, err := agent.StartAWSVPCTaskWithTags("awsvpc-trunking-tags", nil)
	require.NoError(t, err)
	defer func() {
		if err := task.Stop(); err != nil {
			return
		}
		task.WaitStopped(1 * time.Minute)
	}()

	// Wait for task to be running
	err = task.WaitRunning(1 * time.Minute)
	assert.NoError(t, err)

	// check branch ENI tags
	expectedKeys := []string{"test-tag-key"}
	ec2Client := GetEC2Client("")
	tagDescriptions, err := GetResourcesWithTagKeys(ec2Client, expectedKeys)
	require.NoError(t, err)

	// rough check - just check that there's an ENI that's tagged with test-tag-key and has tag value test-tag-value
	var b bool
	for _, tagDescription := range tagDescriptions {
		if aws.StringValue(tagDescription.ResourceType) != "network-interface" {
			continue
		}

		if aws.StringValue(tagDescription.Key) == "test-tag-key" && aws.StringValue(tagDescription.Value) == "test-tag-value" {
			b = true
		}
	}

	assert.True(t, b)
}

func TestENIRegisterToTargetGroup(t *testing.T) {
	// create lb and target group
	subnet, err := GetSubnetID()
	assert.NoError(t, err)

	vpc, err := GetVPCID()
	assert.NoError(t, err)

	elbClient := GetELBClient("")
	loadBalancer, err := CreateLoadBalancer(elbClient, "eni-trunking-manual-test", subnet, "network")
	assert.NoError(t, err)
	loadBalancerARN := aws.StringValue(loadBalancer.LoadBalancerArn)
	fmt.Printf("Created load balancer: %s\n", loadBalancerARN)
	defer func() {
		err := DeleteLoadBalancer(elbClient, loadBalancerARN)
		assert.NoError(t, err)
		fmt.Printf("Deleted load balancer: %s\n", loadBalancerARN)
	}()

	targetGroupARN, err := CreateTargetGroup(elbClient, "eni-trunking-manual-test", "TCP", "ip", vpc, 80)
	assert.NoError(t, err)
	fmt.Printf("Created target group: %s\n", targetGroupARN)
	defer func() {
		err := DeleteTargetGroup(elbClient, targetGroupARN)
		assert.NoError(t, err)
		fmt.Printf("Deleted target group: %s\n", targetGroupARN)
	}()

	listenerARN, err := CreateListener(elbClient, loadBalancerARN, targetGroupARN, "TCP", 80)
	assert.NoError(t, err)
	fmt.Printf("Created listener: %s\n", listenerARN)
	defer func() {
		err := DeleteListener(elbClient, listenerARN)
		assert.NoError(t, err)
		fmt.Printf("Deleted listener: %s\n", listenerARN)
	}()

	start := time.Now()
	err = WaitLoadBalancerActive(elbClient, loadBalancerARN, 5 * time.Minute)
	assert.NoError(t, err)
	fmt.Printf("Load balancer becomes active after %v\n", time.Since(start))

	RequireInstanceTypes(t, []string{"c5", "m5", "r5", "z1d", "a1"})

	enableAccountSetting("awsvpcTrunking", t)

	existingInterfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)

	agentOptions := &AgentOptions{
		EnableTaskENI: true,
	}
	os.Setenv("ECS_FTEST_FORCE_NET_HOST", "true")

	// launch agent
	fmt.Println("Launching Agent")
	agent := RunAgent(t, agentOptions)
	defer func() {
		agent.StopAgent()

		ECS.DeregisterContainerInstance(&ecsapi.DeregisterContainerInstanceInput{
			Cluster:           &agent.Cluster,
			ContainerInstance: &agent.ContainerInstanceArn,
			Force:             aws.Bool(true),
		})

		// Wait and verify that the Trunk ENI is detached
		err = WaitNetworkInterfaceCount(existingInterfaceCount, 1 * time.Minute)
		assert.NoError(t, err)

		agent.TestCleanup()
	}()
	fmt.Printf("Container instance arn: %s\n", agent.ContainerInstanceArn)

	// wait for container instance to reach ACTIVE
	err = agent.WaitContainerInstanceStatus("ACTIVE", 1 * time.Minute)
	assert.NoError(t, err)

	// check ENI attached
	interfaceCount, err := GetNetworkInterfaceCount()
	require.NoError(t, err)
	assert.Equal(t, existingInterfaceCount + 1, interfaceCount)

	// create service
	fmt.Println("Creating service...")
	service, err := agent.CreateService("awsvpc-trunking-nginx", "eni-trunking-manual-test",
		targetGroupARN, "container_1", 80, 1, nil)
	require.NoError(t, err)
	defer func() {
		_, err := ECS.DeleteService(&ecsapi.DeleteServiceInput{
			Cluster: aws.String(agent.Cluster),
			Service: service.ServiceName,
			Force: aws.Bool(true),
		})
		assert.NoError(t, err)

		//start := time.Now()
		//fmt.Println("Waiting for service to be deleted...")
		//err = WaitServiceStatus(agent.Cluster, aws.StringValue(service.ServiceName), "INACTIVE", 10 * time.Minute)
		//assert.NoError(t, err)
		//fmt.Printf("Service %s has reached INACTIVE after %v", aws.StringValue(service.ServiceName), time.Since(start))
	}()

	// try visiting lb url
	fmt.Println("Try visiting LB...")
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	endpoint := fmt.Sprintf("http://%s", aws.StringValue(loadBalancer.DNSName))
	start = time.Now()
	err = WaitEndpointAvailable(client, endpoint, 5 * time.Minute)
	assert.NoError(t, err)
	fmt.Printf("Endpoint %s becomes available after %v", endpoint, time.Since(start))
}

