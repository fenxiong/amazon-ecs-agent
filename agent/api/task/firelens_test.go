// +build linux,unit

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

package task

import (
	"encoding/json"
	"testing"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apicontainerstatus "github.com/aws/amazon-ecs-agent/agent/api/container/status"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/taskresource"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/asmsecret"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/firelens"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/ssmsecret"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostUnmarshalWithFirelensContainer(t *testing.T) {
	task := getFirelensTask(t)

	resourceFields := &taskresource.ResourceFields{
		ResourceFieldsCommon: &taskresource.ResourceFieldsCommon{
			EC2InstanceID: testInstanceID,
		},
	}
	cfg := &config.Config{
		DataDir: testDataDir,
		Cluster: testCluster,
	}
	assert.NoError(t, task.PostUnmarshalTask(cfg, nil, resourceFields, nil, nil))
	resources := task.GetResources()
	assert.Len(t, resources, 2)
	assert.Len(t, task.Containers[1].TransitionDependenciesMap, 1)
	assert.Len(t, task.Containers[1].TransitionDependenciesMap[apicontainerstatus.ContainerCreated].ResourceDependencies, 2)
	var firelensResource *firelens.FirelensResource
	var secretResource *ssmsecret.SSMSecretResource
	for _, resource := range resources {
		if resource.GetName() == firelens.ResourceName {
			firelensResource = resource.(*firelens.FirelensResource)
		} else if resource.GetName() == ssmsecret.ResourceName {
			secretResource = resource.(*ssmsecret.SSMSecretResource)
		}
	}

	assert.NotNil(t, firelensResource)
	assert.NotNil(t, secretResource)

	assert.Equal(t, testCluster, firelensResource.GetCluster())
	assert.Equal(t, validTaskArn, firelensResource.GetTaskARN())
	assert.Equal(t, testTaskDefFamily+":"+testTaskDefVersion, firelensResource.GetTaskDefinition())
	assert.Equal(t, testInstanceID, firelensResource.GetEC2InstanceID())
	assert.Equal(t, testDataDir+"/firelens/task-id", firelensResource.GetResourceDir())
	assert.NotNil(t, firelensResource.GetContainerToLogOptions())
	assert.Equal(t, "value1", firelensResource.GetContainerToLogOptions()["logsender"]["key1"])
	assert.Equal(t, "value2", firelensResource.GetContainerToLogOptions()["logsender"]["key2"])
	assert.Contains(t, task.Containers[0].DependsOnUnsafe, apicontainer.DependsOn{
		ContainerName: task.Containers[1].Name,
		Condition:     ContainerOrderingStartCondition,
	})
}

func TestPostUnmarshalWithFirelensContainerError(t *testing.T) {
	task := getFirelensTask(t)
	task.Containers[0].DockerConfig.HostConfig = strptr(string("invalid"))

	resourceFields := &taskresource.ResourceFields{
		ResourceFieldsCommon: &taskresource.ResourceFieldsCommon{
			EC2InstanceID: testInstanceID,
		},
	}
	cfg := &config.Config{
		DataDir: testDataDir,
		Cluster: testCluster,
	}
	assert.Error(t, task.PostUnmarshalTask(cfg, nil, resourceFields, nil, nil))
}

func TestGetFirelensContainer(t *testing.T) {
	firelensContainer := &apicontainer.Container{
		Name: "c",
		FirelensConfig: &apicontainer.FirelensConfig{
			Type: firelens.FirelensConfigTypeFluentd,
		},
	}

	testCases := []struct {
		name              string
		task              *Task
		firelensContainer *apicontainer.Container
	}{
		{
			name: "task has firelens container",
			task: &Task{
				Containers: []*apicontainer.Container{
					firelensContainer,
				},
			},
			firelensContainer: firelensContainer,
		},
		{
			name: "task doesn't have firelens container",
			task: &Task{
				Containers: []*apicontainer.Container{
					{
						Name: "c",
					},
				},
			},
			firelensContainer: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.firelensContainer, tc.task.getFirelensContainer())
		})
	}
}

func TestInitializeFirelensResource(t *testing.T) {
	cfg := &config.Config{
		DataDir: testDataDir,
		Cluster: testCluster,
	}
	resourceFields := &taskresource.ResourceFields{
		ResourceFieldsCommon: &taskresource.ResourceFieldsCommon{
			EC2InstanceID: testInstanceID,
		},
	}

	testCases := []struct {
		name                  string
		task                  *Task
		shouldFail            bool
		shouldHaveInstanceID  bool
		shouldDisableMetadata bool
		expectedLogOptions    map[string]map[string]string
	}{
		{
			name:                 "test initialize firelens resource fluentd",
			task:                 getFirelensTask(t),
			shouldHaveInstanceID: true,
			expectedLogOptions: map[string]map[string]string{
				"logsender": {
					"key1":        "value1",
					"key2":        "value2",
					"secret-name": "\"#{ENV['secret-name_logsender']}\"",
				},
			},
		},
		{
			name: "test initialize firelens resource fluentbit",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].FirelensConfig.Type = firelens.FirelensConfigTypeFluentbit
				return task
			}(),
			shouldHaveInstanceID: true,
			expectedLogOptions: map[string]map[string]string{
				"logsender": {
					"key1":        "value1",
					"key2":        "value2",
					"secret-name": "${secret-name_logsender}",
				},
			},
		},
		{
			name: "test initialize firelens resource without ec2 instance id",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].Environment = nil
				return task
			}(),
			expectedLogOptions: map[string]map[string]string{
				"logsender": {
					"key1":        "value1",
					"key2":        "value2",
					"secret-name": "\"#{ENV['secret-name_logsender']}\"",
				},
			},
		},
		{
			name: "test initialize firelens resource disables ecs log metadata",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].FirelensConfig.Options["enable-ecs-log-metadata"] = "false"
				return task
			}(),
			shouldHaveInstanceID:  true,
			shouldDisableMetadata: true,
			expectedLogOptions: map[string]map[string]string{
				"logsender": {
					"key1":        "value1",
					"key2":        "value2",
					"secret-name": "\"#{ENV['secret-name_logsender']}\"",
				},
			},
		},
		{
			name: "test initialize firelens resource invalid host config",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[0].DockerConfig.HostConfig = strptr(string("invalid"))
				return task
			}(),
			shouldFail: true,
		},
		{
			name: "test initialize firelens resource no firelens container",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].FirelensConfig = nil
				return task
			}(),
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.task.initializeFirelensResource(cfg, resourceFields, tc.task.Containers[1])
			if tc.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				resources := tc.task.GetResources()
				assert.Equal(t, 1, len(resources))
				assert.Equal(t, 1, len(tc.task.Containers[1].TransitionDependenciesMap))

				firelensResource := resources[0].(*firelens.FirelensResource)
				assert.Equal(t, testCluster, firelensResource.GetCluster())
				assert.Equal(t, validTaskArn, firelensResource.GetTaskARN())
				assert.Equal(t, testTaskDefFamily+":"+testTaskDefVersion, firelensResource.GetTaskDefinition())
				assert.Equal(t, testDataDir+"/firelens/task-id", firelensResource.GetResourceDir())
				assert.NotNil(t, firelensResource.GetContainerToLogOptions())
				assert.Equal(t, tc.expectedLogOptions, firelensResource.GetContainerToLogOptions())
				assert.Equal(t, !tc.shouldDisableMetadata, firelensResource.GetECSMetadataEnabled())

				if tc.shouldHaveInstanceID {
					assert.Equal(t, testInstanceID, firelensResource.GetEC2InstanceID())
				} else {
					assert.Empty(t, firelensResource.GetEC2InstanceID())
				}
			}
		})
	}
}

func TestCollectFirelensLogOptions(t *testing.T) {
	task := getFirelensTask(t)

	containerToLogOptions := make(map[string]map[string]string)
	err := task.collectFirelensLogOptions(containerToLogOptions)
	assert.NoError(t, err)
	assert.Equal(t, "value1", containerToLogOptions["logsender"]["key1"])
	assert.Equal(t, "value2", containerToLogOptions["logsender"]["key2"])
}

func TestCollectFirelensLogOptionsInvalidOptions(t *testing.T) {
	task := getFirelensTask(t)
	task.Containers[0].DockerConfig.HostConfig = strptr(string("invalid"))

	containerToLogOptions := make(map[string]map[string]string)
	err := task.collectFirelensLogOptions(containerToLogOptions)
	assert.Error(t, err)
}

func TestCollectFirelensLogEnvOptions(t *testing.T) {
	task := getFirelensTask(t)

	containerToLogOptions := make(map[string]map[string]string)
	err := task.collectFirelensLogEnvOptions(containerToLogOptions, "fluentd")
	assert.NoError(t, err)
	assert.Equal(t, "\"#{ENV['secret-name_logsender']}\"", containerToLogOptions["logsender"]["secret-name"])
}

func TestAddFirelensContainerDependency(t *testing.T) {
	testCases := []struct {
		name                string
		task                *Task
		shouldAddDependency bool
	}{
		{
			name:                "test adding firelens container dependency",
			task:                getFirelensTask(t),
			shouldAddDependency: true,
		},
		{
			name: "test not adding firelens container dependency case 1",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[0].FirelensConfig = task.Containers[1].FirelensConfig
				task.Containers = task.Containers[:1]
				return task
			}(),
			shouldAddDependency: false,
		},
		{
			name: "test not adding firelens container dependency case 2",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers = append(task.Containers, &apicontainer.Container{
					Name: "container2",
				})
				task.Containers[1].DependsOnUnsafe = append(task.Containers[1].DependsOnUnsafe, apicontainer.DependsOn{
					ContainerName: "container2",
					Condition:     ContainerOrderingStartCondition,
				})
				return task
			}(),
			shouldAddDependency: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.task.addFirelensContainerDependency()
			assert.NoError(t, err)

			if tc.shouldAddDependency {
				assert.Equal(t, 1, len(tc.task.Containers[0].DependsOnUnsafe))
				assert.Equal(t, tc.task.Containers[1].Name, tc.task.Containers[0].DependsOnUnsafe[0].ContainerName)
				assert.Equal(t, ContainerOrderingStartCondition, tc.task.Containers[0].DependsOnUnsafe[0].Condition)
			} else {
				assert.Empty(t, tc.task.Containers[0].DependsOnUnsafe)
			}
		})
	}
}

func TestAddFirelensContainerBindMounts(t *testing.T) {
	cfg := &config.Config{
		DataDirOnHost: testDataDirOnHost,
	}

	testCases := []struct {
		name               string
		task               *Task
		firelensConfigType string
		hostCfg            *dockercontainer.HostConfig
		cfg                *config.Config
		shouldFail         bool
		expectedBindMounts []string
	}{
		{
			name:               "test add bind mounts for fluentd firelens container",
			task:               getFirelensTask(t),
			firelensConfigType: firelens.FirelensConfigTypeFluentd,
			hostCfg:            &dockercontainer.HostConfig{},
			cfg:                cfg,
			shouldFail:         false,
			expectedBindMounts: []string{
				"testDataDirOnHost/data/firelens/task-id/config/fluent.conf:/fluentd/etc/fluent.conf",
				"testDataDirOnHost/data/firelens/task-id/socket/:/var/run/",
			},
		},
		{
			name: "test add bind mounts for fluentbit firelens container",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].FirelensConfig.Type = firelens.FirelensConfigTypeFluentbit
				return task
			}(),
			firelensConfigType: firelens.FirelensConfigTypeFluentbit,
			hostCfg:            &dockercontainer.HostConfig{},
			cfg:                cfg,
			shouldFail:         false,
			expectedBindMounts: []string{
				"testDataDirOnHost/data/firelens/task-id/config/fluent.conf:/fluent-bit/etc/fluent-bit.conf",
				"testDataDirOnHost/data/firelens/task-id/socket/:/var/run/",
			},
		},
		{
			name: "test add bind mounts invalid firelens configuration type",
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[1].FirelensConfig.Type = "invalid"
				return task
			}(),
			firelensConfigType: "invalid",
			hostCfg:            &dockercontainer.HostConfig{},
			cfg:                cfg,
			shouldFail:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.task.AddFirelensContainerBindMounts(tc.firelensConfigType, tc.hostCfg, tc.cfg)
			if tc.shouldFail {
				// assert.Error doesn't work with *apierrors.HostConfigError.
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tc.expectedBindMounts, tc.hostCfg.Binds)
			}
		})
	}
}

func TestFirelensDependsOnSecretResource(t *testing.T) {
	testCases := []struct {
		name     string
		provider string
		task     *Task
		res      bool
	}{
		{
			name:     "depends on ssm",
			provider: apicontainer.SecretProviderSSM,
			task:     getFirelensTask(t),
			res:      true,
		},
		{
			name:     "depends on asm",
			provider: apicontainer.SecretProviderASM,
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[0].Secrets[0].Provider = apicontainer.SecretProviderASM
				return task
			}(),
			res: true,
		},
		{
			name:     "no dependency",
			provider: apicontainer.SecretProviderSSM,
			task: func() *Task {
				task := getFirelensTask(t)
				task.Containers[0].Secrets = []apicontainer.Secret{}
				return task
			}(),
			res: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.res, tc.task.firelensDependsOnSecretResource(tc.provider))
		})
	}
}

func TestPopulateSecretLogOptionsToFirelensContainer(t *testing.T) {
	task := getFirelensTask(t)
	ssmRes := &ssmsecret.SSMSecretResource{}
	ssmRes.SetCachedSecretValue("secret-value-from_us-west-2", "secret-val")
	task.AddResource(ssmsecret.ResourceName, ssmRes)

	assert.Nil(t, task.PopulateSecretLogOptionsToFirelensContainer(task.Containers[1]))
	assert.Len(t, task.Containers[1].Environment, 2)
	assert.Equal(t, "secret-val", task.Containers[1].Environment["secret-name_logsender"])
}

func TestCollectLogDriverSecretData(t *testing.T) {
	ssmRes := &ssmsecret.SSMSecretResource{}
	ssmRes.SetCachedSecretValue("secret-value-from_us-west-2", "secret-val")

	asmRes := &asmsecret.ASMSecretResource{}
	asmRes.SetCachedSecretValue("secret-value-from-asm_us-west-2", "secret-val-asm")

	secrets := []apicontainer.Secret{
		{
			Name:      "secret-name",
			Provider:  apicontainer.SecretProviderSSM,
			Target:    apicontainer.SecretTargetLogDriver,
			ValueFrom: "secret-value-from",
			Region:    "us-west-2",
		},
		{
			Name:      "secret-name-asm",
			Provider:  apicontainer.SecretProviderASM,
			Target:    apicontainer.SecretTargetLogDriver,
			ValueFrom: "secret-value-from-asm",
			Region:    "us-west-2",
		},
	}

	secretData, err := collectLogDriverSecretData(secrets, ssmRes, asmRes)
	assert.NoError(t, err)
	assert.Len(t, secretData, 2)
	assert.Equal(t, "secret-val", secretData["secret-name"])
	assert.Equal(t, "secret-val-asm", secretData["secret-name-asm"])
}

// getFirelensTask returns a sample firelens task.
func getFirelensTask(t *testing.T) *Task {
	rawHostConfigInput := dockercontainer.HostConfig{
		LogConfig: dockercontainer.LogConfig{
			Type: firelensDriverName,
			Config: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	rawHostConfig, err := json.Marshal(&rawHostConfigInput)
	require.NoError(t, err)

	return &Task{
		Arn:                validTaskArn,
		Family:             testTaskDefFamily,
		Version:            testTaskDefVersion,
		ResourcesMapUnsafe: make(map[string][]taskresource.TaskResource),
		Containers: []*apicontainer.Container{
			{
				Name: "logsender",
				DockerConfig: apicontainer.DockerConfig{
					HostConfig: strptr(string(rawHostConfig)),
				},
				Secrets: []apicontainer.Secret{
					{
						Name:      "secret-name",
						ValueFrom: "secret-value-from",
						Region:    "us-west-2",

						Target:   apicontainer.SecretTargetLogDriver,
						Provider: apicontainer.SecretProviderSSM,
					},
				},
				TransitionDependenciesMap: make(map[apicontainerstatus.ContainerStatus]apicontainer.TransitionDependencySet),
			},
			{
				Name: "firelenscontainer",
				FirelensConfig: &apicontainer.FirelensConfig{
					Type: firelens.FirelensConfigTypeFluentd,
					Options: map[string]string{
						"enable-ecs-log-metadata": "true",
					},
				},
				Environment: map[string]string{
					"AWS_EXECUTION_ENV": "AWS_ECS_EC2",
				},
				TransitionDependenciesMap: make(map[apicontainerstatus.ContainerStatus]apicontainer.TransitionDependencySet),
			},
		},
	}
}

