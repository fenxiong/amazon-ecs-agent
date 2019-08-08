// +build linux

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
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apicontainerstatus "github.com/aws/amazon-ecs-agent/agent/api/container/status"
	apierrors "github.com/aws/amazon-ecs-agent/agent/api/errors"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/taskresource"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/asmsecret"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/firelens"
	"github.com/aws/amazon-ecs-agent/agent/taskresource/ssmsecret"
	resourcestatus "github.com/aws/amazon-ecs-agent/agent/taskresource/status"

	"github.com/cihub/seelog"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/pkg/errors"
)

const (
	// firelensConfigBindFormatFluentd and firelensConfigBindFormatFluentbit specifies the format of the firelens
	// config file bind mount for fluentd and fluentbit firelens container respectively.
	// First placeholder is host data dir, second placeholder is taskID.
	firelensConfigBindFormatFluentd   = "%s/data/firelens/%s/config/fluent.conf:/fluentd/etc/fluent.conf"
	firelensConfigBindFormatFluentbit = "%s/data/firelens/%s/config/fluent.conf:/fluent-bit/etc/fluent-bit.conf"
	// firelensSocketBindFormat specifies the format for firelens container's socket directory bind mount.
	// First placeholder is host data dir, second placeholder is taskID.
	firelensSocketBindFormat = "%s/data/firelens/%s/socket/:/var/run/"
	// firelensDriverName is the log driver name for containers that want to use the firelens container to send logs.
	firelensDriverName = "awsfirelens"

	// firelensConfigVarFmt specifies the format for firelens config variable name. The first placeholder
	// is option name. The second placeholder is container name.
	firelensConfigVarFmt = "%s_%s"
	// firelensConfigVarPlaceholderFmtFluentd and firelensConfigVarPlaceholderFmtFluentbit specify the config var
	// placeholder format expected by fluentd and fluentbit respectively.
	firelensConfigVarPlaceholderFmtFluentd   = "\"#{ENV['%s']}\""
	firelensConfigVarPlaceholderFmtFluentbit = "${%s}"

	logDriverTypeFluentd    = "fluentd"
	logDriverTag            = "tag"
	logDriverFluentdAddress = "fluentd-address"
	dataLogDriverPath       = "/data/firelens/"
	logDriverAsyncConnect   = "fluentd-async-connect"
	dataLogDriverSocketPath = "/socket/fluent.sock"
	socketPathPrefix        = "unix://"
)

// getFirelensContainer returns the firelens container in the task, if there is one.
func (task *Task) getFirelensContainer() *apicontainer.Container {
	for _, container := range task.Containers {
		if container.GetFirelensConfig() != nil { // This is a firelens container.
			return container
		}
	}
	return nil
}

// firelensDependsOnSecret checks whether the firelens container needs to depends on a secret resource of
// a certain provider type.
func (task *Task) firelensDependsOnSecretResource(secretProvider string) bool {
	isLogDriverSecretWithGivenProvider := func(s apicontainer.Secret) bool {
		return s.Provider == secretProvider && s.Target == apicontainer.SecretTargetLogDriver
	}
	for _, container := range task.Containers {
		if container.GetLogDriver() == firelensDriverName && container.HasSecret(isLogDriverSecretWithGivenProvider) {
			return true
		}
	}
	return false
}

func (task *Task) applyFirelensSetup(cfg *config.Config, resourceFields *taskresource.ResourceFields,
	firelensContainer *apicontainer.Container) error {
	err := task.initializeFirelensResource(cfg, resourceFields, firelensContainer)
	if err != nil {
		return apierrors.NewResourceInitError(task.Arn, err)
	}
	err = task.addFirelensContainerDependency()
	if err != nil {
		return errors.New("unable to add firelens container dependency")
	}

	return nil
}

// initializeFirelensResource initializes the firelens task resource and adds it as a dependency of the
// firelens container.
func (task *Task) initializeFirelensResource(config *config.Config, resourceFields *taskresource.ResourceFields,
	firelensContainer *apicontainer.Container) error {
	if firelensContainer.GetFirelensConfig() == nil {
		return errors.New("firelens container config doesn't exist")
	}

	containerToLogOptions := make(map[string]map[string]string)
	// Collect plain text log options.
	err := task.collectFirelensLogOptions(containerToLogOptions)
	if err != nil {
		return errors.Wrap(err, "unable to initialize firelens resource")
	}

	// Collect secret log options.
	err = task.collectFirelensLogEnvOptions(containerToLogOptions, firelensContainer.FirelensConfig.Type)
	if err != nil {
		return errors.Wrap(err, "unable to initialize firelens resource")
	}

	var firelensResource *firelens.FirelensResource
	for _, container := range task.Containers {
		firelensConfig := container.GetFirelensConfig()
		if firelensConfig != nil {
			var ec2InstanceID string
			if container.Environment != nil && container.Environment[awsExecutionEnvKey] == ec2ExecutionEnv {
				ec2InstanceID = resourceFields.EC2InstanceID
			}

			enableECSLogMetadata := true
			if firelensConfig.Options != nil && firelensConfig.Options["enable-ecs-log-metadata"] == "false" {
				enableECSLogMetadata = false
			}

			firelensResource = firelens.NewFirelensResource(config.Cluster, task.Arn, task.Family+":"+task.Version,
				ec2InstanceID, config.DataDir, firelensConfig.Type, enableECSLogMetadata, containerToLogOptions)
			task.AddResource(firelens.ResourceName, firelensResource)
			container.BuildResourceDependency(firelensResource.GetName(), resourcestatus.ResourceCreated,
				apicontainerstatus.ContainerCreated)
			return nil
		}
	}

	return errors.New("unable to initialize firelens resource because there's no firelens container")
}

// addFirelensContainerDependency adds a START dependency between each container using awsfirelens log driver
// and the firelens container.
func (task *Task) addFirelensContainerDependency() error {
	var firelensContainer *apicontainer.Container
	for _, container := range task.Containers {
		if container.GetFirelensConfig() != nil {
			firelensContainer = container
		}
	}

	if firelensContainer == nil {
		return errors.New("unable to add firelens container dependency because there's no firelens container")
	}

	if firelensContainer.HasContainerDependencies() {
		// If firelens container has any container dependency, we don't add internal container dependency that depends
		// on it in order to be safe (otherwise we need to deal with circular dependency).
		seelog.Warnf("Not adding container dependency to let firelens container %s start first, because it has dependency on other containers.", firelensContainer.Name)
		return nil
	}

	for _, container := range task.Containers {
		containerHostConfig := container.GetHostConfig()
		if containerHostConfig == nil {
			continue
		}

		// Firelens container itself could be using awsfirelens log driver. Don't add container dependency in this case.
		if container.Name == firelensContainer.Name {
			continue
		}

		hostConfig := &dockercontainer.HostConfig{}
		err := json.Unmarshal([]byte(*containerHostConfig), hostConfig)
		if err != nil {
			return errors.Wrapf(err, "unable to decode host config of container %s", container.Name)
		}

		if hostConfig.LogConfig.Type == firelensDriverName {
			// If there's no dependency between the app container and the firelens container, make firelens container
			// start first to be the default behavior by adding a START container depdendency.
			if !container.DependsOnContainer(firelensContainer.Name) {
				seelog.Infof("Adding a START container dependency on firelens container %s for container %s",
					firelensContainer.Name, container.Name)
				container.AddContainerDependency(firelensContainer.Name, ContainerOrderingStartCondition)
			}
		}
	}

	return nil
}

// collectFirelensLogOptions collects the log options for all the containers that use the firelens container
// as the log driver.
// containerToLogOptions is a nested map. Top level key is the container name. Second level is a map storing
// the log option key and value of the container.
func (task *Task) collectFirelensLogOptions(containerToLogOptions map[string]map[string]string) error {
	for _, container := range task.Containers {
		if container.DockerConfig.HostConfig == nil {
			continue
		}

		hostConfig := &dockercontainer.HostConfig{}
		err := json.Unmarshal([]byte(*container.DockerConfig.HostConfig), hostConfig)
		if err != nil {
			return errors.Wrapf(err, "unable to decode host config of container %s", container.Name)
		}

		if hostConfig.LogConfig.Type == firelensDriverName {
			if containerToLogOptions[container.Name] == nil {
				containerToLogOptions[container.Name] = make(map[string]string)
			}
			for k, v := range hostConfig.LogConfig.Config {
				containerToLogOptions[container.Name][k] = v
			}
		}
	}

	return nil
}

// collectFirelensLogEnvOptions collects all the log secret options. Each secret log option will have a value
// of a config file variable (e.g. "${config_var_name}") and we will pass the secret value as env to the firelens
// container and it will resolve the config file variable from the env.
// Each config variable name has a format of log-option-key_container-name. We need the container name because options
// from different containers using awsfirelens log driver in a task will be presented in the same firelens config file.
func (task *Task) collectFirelensLogEnvOptions(containerToLogOptions map[string]map[string]string, firelensConfigType string) error {
	placeholderFmt := ""
	switch firelensConfigType {
	case firelens.FirelensConfigTypeFluentd:
		placeholderFmt = firelensConfigVarPlaceholderFmtFluentd
	case firelens.FirelensConfigTypeFluentbit:
		placeholderFmt = firelensConfigVarPlaceholderFmtFluentbit
	default:
		return errors.Errorf("unsupported firelens config type %s", firelensConfigType)
	}

	for _, container := range task.Containers {
		for _, secret := range container.Secrets {
			if secret.Target == apicontainer.SecretTargetLogDriver {
				if containerToLogOptions[container.Name] == nil {
					containerToLogOptions[container.Name] = make(map[string]string)
				}

				containerToLogOptions[container.Name][secret.Name] = fmt.Sprintf(placeholderFmt,
					fmt.Sprintf(firelensConfigVarFmt, secret.Name, container.Name))
			}
		}
	}
	return nil
}

// AddFirelensContainerBindMounts adds config file bind mount and socket directory bind mount to the firelens
// container's host config.
func (task *Task) AddFirelensContainerBindMounts(firelensConfigType string, hostConfig *dockercontainer.HostConfig,
	config *config.Config) *apierrors.HostConfigError {
	// TODO: fix task.GetID(). It's currently incorrect when opted in task long arn format.
	fields := strings.Split(task.Arn, "/")
	taskID := fields[len(fields)-1]

	var configBind, socketBind string
	switch firelensConfigType {
	case firelens.FirelensConfigTypeFluentd:
		configBind = fmt.Sprintf(firelensConfigBindFormatFluentd, config.DataDirOnHost, taskID)
	case firelens.FirelensConfigTypeFluentbit:
		configBind = fmt.Sprintf(firelensConfigBindFormatFluentbit, config.DataDirOnHost, taskID)
	default:
		return &apierrors.HostConfigError{Msg: fmt.Sprintf("encounter invalid firelens configuration type %s",
			firelensConfigType)}
	}
	socketBind = fmt.Sprintf(firelensSocketBindFormat, config.DataDirOnHost, taskID)

	hostConfig.Binds = append(hostConfig.Binds, configBind, socketBind)
	return nil
}

// PopulateSecretLogOptionsToFirelensContainer collects secret log option values for awsfirelens log driver from task
// resource and specified then as envs of firelens container. Firelens container will use the envs to resolve config
// file variables constructed for secret log options when loading the config file.
func (task *Task) PopulateSecretLogOptionsToFirelensContainer(firelensContainer *apicontainer.Container) *apierrors.DockerClientConfigError {
	firelensENVs := make(map[string]string)

	var ssmRes *ssmsecret.SSMSecretResource
	var asmRes *asmsecret.ASMSecretResource

	resource, ok := task.getSSMSecretsResource()
	if ok {
		ssmRes = resource[0].(*ssmsecret.SSMSecretResource)
	}

	resource, ok = task.getASMSecretsResource()
	if ok {
		asmRes = resource[0].(*asmsecret.ASMSecretResource)
	}

	for _, container := range task.Containers {
		if container.GetLogDriver() != firelensDriverName {
			continue
		}

		logDriverSecretData, err := collectLogDriverSecretData(container.Secrets, ssmRes, asmRes)
		if err != nil {
			return &apierrors.DockerClientConfigError{
				Msg: fmt.Sprintf("unable to generate config to create firelens container: %v", err),
			}
		}

		for key, value := range logDriverSecretData {
			envKey := fmt.Sprintf(firelensConfigVarFmt, key, container.Name)
			firelensENVs[envKey] = value
		}
	}

	firelensContainer.MergeEnvironmentVariables(firelensENVs)
	return nil
}

// collectLogDriverSecretData collects all the secret values for log driver secrets.
func collectLogDriverSecretData(secrets []apicontainer.Secret, ssmRes *ssmsecret.SSMSecretResource,
	asmRes *asmsecret.ASMSecretResource) (map[string]string, error) {
	secretData := make(map[string]string)
	for _, secret := range secrets {
		if secret.Target != apicontainer.SecretTargetLogDriver {
			continue
		}

		secretVal := ""
		cacheKey := secret.GetSecretResourceCacheKey()
		if secret.Provider == apicontainer.SecretProviderSSM {
			if ssmRes == nil {
				return nil, errors.Errorf("missing secret value for secret %s", secret.Name)
			}

			if secretValue, ok := ssmRes.GetCachedSecretValue(cacheKey); ok {
				secretVal = secretValue
			}
		} else if secret.Provider == apicontainer.SecretProviderASM {
			if asmRes == nil {
				return nil, errors.Errorf("missing secret value for secret %s", secret.Name)
			}

			if secretValue, ok := asmRes.GetCachedSecretValue(cacheKey); ok {
				secretVal = secretValue
			}
		}

		secretData[secret.Name] = secretVal
	}

	return secretData, nil
}

func (task *Task) GetFirelensDriverLogConfig(container *apicontainer.Container, hostConfig *dockercontainer.HostConfig, cfg *config.Config) dockercontainer.LogConfig {
	fields := strings.Split(task.Arn, "/")
	taskID := fields[len(fields)-1]
	tag := container.Name + "-" + taskID
	fluentd := socketPathPrefix + filepath.Join(cfg.DataDirOnHost, dataLogDriverPath, taskID, dataLogDriverSocketPath)
	logConfig := hostConfig.LogConfig
	logConfig.Type = logDriverTypeFluentd
	logConfig.Config = make(map[string]string)
	logConfig.Config[logDriverTag] = tag
	logConfig.Config[logDriverFluentdAddress] = fluentd
	logConfig.Config[logDriverAsyncConnect] = strconv.FormatBool(true)
	seelog.Debugf("Applying firelens log config for container %s: %v", container.Name, logConfig)
	return logConfig
}