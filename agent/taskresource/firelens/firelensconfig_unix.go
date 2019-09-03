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

package firelens

import (
	"fmt"

	"github.com/cihub/seelog"
	"github.com/pkg/errors"

	generator "github.com/awslabs/go-config-generator-for-fluentd-and-fluentbit"
)

const (
	// FirelensConfigTypeFluentd is the type of a fluentd firelens container.
	FirelensConfigTypeFluentd = "fluentd"

	// FirelensConfigTypeFluentbit is the type of a fluentbit firelens container.
	FirelensConfigTypeFluentbit = "fluentbit"

	// socketInputNameFluentd is the name of the socket input plugin for fluentd.
	socketInputNameFluentd = "unix"

	// inputNameForward is the name of the tcp socket input plugin for fluentd and fluentbit.
	inputNameForward = "forward"

	// socketInputPathOptionFluentd is the key for specifying socket path for fluentd.
	socketInputPathOptionFluentd = "path"

	// socketInputPathOptionFluentbit is the key for specifying socket path for fluentbit.
	socketInputPathOptionFluentbit = "unix_path"

	// outputTypeLogOptionKeyFluentd is the key for the log option that specifies output plugin type for fluentd.
	outputTypeLogOptionKeyFluentd = "@type"

	// outputTypeLogOptionKeyFluentbit is the key for the log option that specifies output plugin type for fluentbit.
	outputTypeLogOptionKeyFluentbit = "Name"

	// includePatternKey is the key for include pattern.
	includePatternKey = "include-pattern"

	// excludePatternKey is the key for exclude pattern.
	excludePatternKey = "exclude-pattern"

	// socketPath is the path for socket file.
	socketPath = "/var/run/fluent.sock"

	// S3ConfigPathFluentd and S3ConfigPathFluentbit are the paths where we bind mount the config downloaded from S3 to.
	S3ConfigPathFluentd   = "/fluentd/etc/external.conf"
	S3ConfigPathFluentbit = "/fluent-bit/etc/external.conf"

	// fluentTagOutputFormat is the format for the log tag, which is container name with "-firelens" appended
	fluentTagOutputFormat = "%s-firelens*"

	// inputBindOptionFluentd is the key for specifying host for fluentd for tcp.
	inputBindOptionFluentd = "bind"

	// inputBridgeBindValue is the value for specifying host for Bridge mode.
	inputBridgeBindValue = "0.0.0.0"

	// inputAWSVPCBindValue is the value for specifying host for AWSVPC mode.
	inputAWSVPCBindValue = "127.0.0.1"

	// inputPortOptionFluentd is the key for specifying port for fluentd for tcp.
	inputPortOptionFluentd = "port"

	// inputPortValue is the value for specifying port for fluentd for tcp.
	inputPortValue = "24224"

	// healthcheckInputNameFluentbit in the input plugin used to receive health check message for fluentbit.
	healthcheckInputNameFluentbit = "tcp"
	// healthcheckInputBindValue is the source where health check message comes from.
	healthcheckInputBindValue = "127.0.0.1"
	// healthcheckInputPortValue is the port for healthcheck.
	healthcheckInputPortValue = "8877"
	// healthcheckTag is the tag for health check message.
	healthcheckTag = "firelens-healthcheck"
	// healthcheckOutputName is the output plugin that health check message goes to. It's a black hole so that the health
	// check messages don't go into logs.
	healthcheckOutputName = "null"

	// inputListenOptionFluentbit is the key for the log option that specifies host for fluentbit.
	inputListenOptionFluentbit = "Listen"

	// inputPortOptionFluentbit is the key for the log option that specifies port for fluentbit.
	inputPortOptionFluentbit = "Port"

	// bridgeNetworkMode specifies bridge type mode for a task
	bridgeNetworkMode = "bridge"

	// specifies awsvpc type mode for a task
	awsvpcNetworkMode = "awsvpc"
)

// generateConfig generates a FluentConfig object that contains all necessary information to construct
// a fluentd or fluentbit config file for a firelens container.
func (firelens *FirelensResource) generateConfig() (generator.FluentConfig, error) {
	config := generator.New()

	// Specify log stream input, which is a unix socket that will be used for communication between the Firelens
	// container and other containers.
	var inputName, inputPathOption string
	if firelens.firelensConfigType == FirelensConfigTypeFluentd {
		inputName = socketInputNameFluentd
		inputPathOption = socketInputPathOptionFluentd
	} else {
		inputName = inputNameForward
		inputPathOption = socketInputPathOptionFluentbit
	}
	config.AddInput(inputName, "", map[string]string{
		inputPathOption: socketPath,
	})
	// Specify log stream input of tcp socket kind that can be used for communication between the Firelens
	// container and other containers if the network is bridge or awsvpc mode. Also add health check sections to support
	// doing container health check on firlens container for these two modes.
	if firelens.networkMode == bridgeNetworkMode || firelens.networkMode == awsvpcNetworkMode {
		inputMap := map[string]string{}
		var inputBindValue string
		if firelens.networkMode == bridgeNetworkMode {
			inputBindValue = inputBridgeBindValue
		} else if firelens.networkMode == awsvpcNetworkMode {
			inputBindValue = inputAWSVPCBindValue
		}
		if firelens.firelensConfigType == FirelensConfigTypeFluentd {
			inputMap = map[string]string{
				inputPortOptionFluentd: inputPortValue,
				inputBindOptionFluentd: inputBindValue,
			}
			inputName = inputNameForward
		} else {
			inputName = inputNameForward
			inputMap = map[string]string{
				inputPortOptionFluentbit:   inputPortValue,
				inputListenOptionFluentbit: inputBindValue,
			}
		}
		config.AddInput(inputName, "", inputMap)

		firelens.addHealthcheckSections(config)
	}

	if firelens.ecsMetadataEnabled {
		// Add ecs metadata fields to the log stream.
		config.AddFieldToRecord("ecs_cluster", firelens.cluster, "*").
			AddFieldToRecord("ecs_task_arn", firelens.taskARN, "*").
			AddFieldToRecord("ecs_task_definition", firelens.taskDefinition, "*")
		if firelens.ec2InstanceID != "" {
			config.AddFieldToRecord("ec2_instance_id", firelens.ec2InstanceID, "*")
		}
	}

	// Specify log stream output. Each container that uses the firelens container to stream logs
	// may have its own output section with options, constructed from container's log options.
	for containerName, logOptions := range firelens.containerToLogOptions {
		tag := fmt.Sprintf(fluentTagOutputFormat, containerName) // Each output section is distinguished by a tag specific to a container.
		newConfig, err := addOutputSection(tag, firelens.firelensConfigType, logOptions, config)
		if err != nil {
			return nil, fmt.Errorf("unable to apply log options of container %s to firelens config: %v", containerName, err)
		}
		config = newConfig
	}

	// Include external config file if specified.
	if firelens.externalConfigType == ExternalConfigTypeFile {
		config.AddExternalConfig(firelens.externalConfigValue, generator.AfterFilters)
	} else if firelens.externalConfigType == ExternalConfigTypeS3 {
		var s3ConfPath string
		if firelens.firelensConfigType == FirelensConfigTypeFluentd {
			s3ConfPath = S3ConfigPathFluentd
		} else {
			s3ConfPath = S3ConfigPathFluentbit
		}
		config.AddExternalConfig(s3ConfPath, generator.AfterFilters)
	}
	seelog.Infof("Included external firelens config file at: %s", firelens.externalConfigValue)

	return config, nil
}

// addHealthcheckSections adds a health check input section and a health check output section to the config.
func (firelens *FirelensResource) addHealthcheckSections(config generator.FluentConfig) {
	// Health check supported is only added for fluentbit.
	if firelens.firelensConfigType != FirelensConfigTypeFluentbit {
		return
	}

	// Add healthcheck input section.
	inputName := healthcheckInputNameFluentbit
	inputOptions := map[string]string{
		inputPortOptionFluentbit:   healthcheckInputPortValue,
		inputListenOptionFluentbit: healthcheckInputBindValue,
	}
	config.AddInput(inputName, healthcheckTag, inputOptions)

	// Add healthcheck output section.
	config.AddOutput(healthcheckOutputName, healthcheckTag, nil)
}

// addOutputSection adds an output section to the firelens container's config that specifies how it routes another
// container's logs. It's constructed based on that container's log options.
// logOptions is a set of key-value pairs, which includes the following:
//     1. The name of the output plugin (required when there are output options specified, i.e. the ones in 4). For
//     fluentd, the key is "@type", for fluentbit, the key is "Name".
//     2. include-pattern (optional): a regex specifying the logs to be included.
//     3. exclude-pattern (optional): a regex specifying the logs to be excluded.
//     4. All other key-value pairs are customer specified options for the plugin. They are unique for each plugin and
//        we don't check them.
func addOutputSection(tag, firelensConfigType string, logOptions map[string]string, config generator.FluentConfig) (generator.FluentConfig, error) {
	var outputKey string
	if firelensConfigType == FirelensConfigTypeFluentd {
		outputKey = outputTypeLogOptionKeyFluentd
	} else {
		outputKey = outputTypeLogOptionKeyFluentbit
	}

	outputOptions := make(map[string]string)
	for key, value := range logOptions {
		switch key {
		case outputKey:
			continue
		case includePatternKey:
			config.AddIncludeFilter(value, "log", tag)
		case excludePatternKey:
			config.AddExcludeFilter(value, "log", tag)
		default: // This is a plugin specific option.
			outputOptions[key] = value
		}
	}

	output, ok := logOptions[outputKey]
	// If there are some output options specified, there must be an output key so that we know what is the output plugin.
	if len(outputOptions) > 0 && !ok {
		return config, errors.New(
			fmt.Sprintf("missing output key %s which is required for firelens configuration of type %s",
				outputKey, firelensConfigType))
	} else if !ok { // Otherwise it's ok to not generate an output section, since customers may specify the output in external config.
		return config, nil
	}

	// Output key is specified. Add an output section.
	config.AddOutput(output, tag, outputOptions)
	return config, nil
}
