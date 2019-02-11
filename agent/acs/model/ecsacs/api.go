// Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package ecsacs

import "github.com/aws/aws-sdk-go/aws/awsutil"

type ASMAuthData struct {
	_ struct{} `type:"structure"`

	CredentialsParameter *string `locationName:"credentialsParameter" type:"string"`

	Region *string `locationName:"region" type:"string"`
}

// String returns the string representation
func (s ASMAuthData) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ASMAuthData) GoString() string {
	return s.String()
}

type AccessDeniedException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s AccessDeniedException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AccessDeniedException) GoString() string {
	return s.String()
}

type AckRequest struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s AckRequest) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AckRequest) GoString() string {
	return s.String()
}

type Association struct {
	_ struct{} `type:"structure"`

	Containers []*string `locationName:"containers" type:"list"`

	Content *EncodedString `locationName:"content" type:"structure"`

	Name *string `locationName:"name" type:"string"`

	Type *string `locationName:"type" type:"string" enum:"AssociationType"`
}

// String returns the string representation
func (s Association) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s Association) GoString() string {
	return s.String()
}

type AttachInstanceNetworkInterfacesInput struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	ElasticNetworkInterfaces []*ElasticNetworkInterface `locationName:"elasticNetworkInterfaces" type:"list"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	WaitTimeoutMs *int64 `locationName:"waitTimeoutMs" type:"long"`
}

// String returns the string representation
func (s AttachInstanceNetworkInterfacesInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachInstanceNetworkInterfacesInput) GoString() string {
	return s.String()
}

type AttachInstanceNetworkInterfacesMessage struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	ElasticNetworkInterfaces []*ElasticNetworkInterface `locationName:"elasticNetworkInterfaces" type:"list"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	WaitTimeoutMs *int64 `locationName:"waitTimeoutMs" type:"long"`
}

// String returns the string representation
func (s AttachInstanceNetworkInterfacesMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachInstanceNetworkInterfacesMessage) GoString() string {
	return s.String()
}

type AttachInstanceNetworkInterfacesOutput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s AttachInstanceNetworkInterfacesOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachInstanceNetworkInterfacesOutput) GoString() string {
	return s.String()
}

type AttachTaskNetworkInterfacesInput struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	ElasticNetworkInterfaces []*ElasticNetworkInterface `locationName:"elasticNetworkInterfaces" type:"list"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	TaskArn *string `locationName:"taskArn" type:"string"`

	WaitTimeoutMs *int64 `locationName:"waitTimeoutMs" type:"long"`
}

// String returns the string representation
func (s AttachTaskNetworkInterfacesInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachTaskNetworkInterfacesInput) GoString() string {
	return s.String()
}

type AttachTaskNetworkInterfacesMessage struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	ElasticNetworkInterfaces []*ElasticNetworkInterface `locationName:"elasticNetworkInterfaces" type:"list"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	TaskArn *string `locationName:"taskArn" type:"string"`

	WaitTimeoutMs *int64 `locationName:"waitTimeoutMs" type:"long"`
}

// String returns the string representation
func (s AttachTaskNetworkInterfacesMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachTaskNetworkInterfacesMessage) GoString() string {
	return s.String()
}

type AttachTaskNetworkInterfacesOutput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s AttachTaskNetworkInterfacesOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachTaskNetworkInterfacesOutput) GoString() string {
	return s.String()
}

type BadRequestException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s BadRequestException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s BadRequestException) GoString() string {
	return s.String()
}

type CloseMessage struct {
	_ struct{} `type:"structure"`

	Message *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s CloseMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s CloseMessage) GoString() string {
	return s.String()
}

type Container struct {
	_ struct{} `type:"structure"`

	Command []*string `locationName:"command" type:"list"`

	Cpu *int64 `locationName:"cpu" type:"integer"`

	DependsOn []*ContainerDependency `locationName:"dependsOn" type:"list"`

	DockerConfig *DockerConfig `locationName:"dockerConfig" type:"structure"`

	EntryPoint []*string `locationName:"entryPoint" type:"list"`

	Environment map[string]*string `locationName:"environment" type:"map"`

	Essential *bool `locationName:"essential" type:"boolean"`

	HealthCheckType *string `locationName:"healthCheckType" type:"string" enum:"HealthCheckType"`

	Image *string `locationName:"image" type:"string"`

	Links []*string `locationName:"links" type:"list"`

	LogsAuthStrategy *string `locationName:"logsAuthStrategy" type:"string" enum:"AuthStrategy"`

	Memory *int64 `locationName:"memory" type:"integer"`

	MountPoints []*MountPoint `locationName:"mountPoints" type:"list"`

	Name *string `locationName:"name" type:"string"`

	Overrides *string `locationName:"overrides" type:"string"`

	PortMappings []*PortMapping `locationName:"portMappings" type:"list"`

	RegistryAuthentication *RegistryAuthenticationData `locationName:"registryAuthentication" type:"structure"`

	Secrets []*Secret `locationName:"secrets" type:"list"`

	StartTimeout *int64 `locationName:"startTimeout" type:"integer"`

	StopTimeout *int64 `locationName:"stopTimeout" type:"integer"`

	VolumesFrom []*VolumeFrom `locationName:"volumesFrom" type:"list"`
}

// String returns the string representation
func (s Container) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s Container) GoString() string {
	return s.String()
}

type ContainerDependency struct {
	_ struct{} `type:"structure"`

	Condition *string `locationName:"condition" type:"string" enum:"ContainerCondition"`

	ContainerName *string `locationName:"containerName" type:"string"`
}

// String returns the string representation
func (s ContainerDependency) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ContainerDependency) GoString() string {
	return s.String()
}

type DockerConfig struct {
	_ struct{} `type:"structure"`

	Config *string `locationName:"config" type:"string"`

	HostConfig *string `locationName:"hostConfig" type:"string"`

	Version *string `locationName:"version" type:"string"`
}

// String returns the string representation
func (s DockerConfig) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s DockerConfig) GoString() string {
	return s.String()
}

type DockerVolumeConfiguration struct {
	_ struct{} `type:"structure"`

	Autoprovision *bool `locationName:"autoprovision" type:"boolean"`

	Driver *string `locationName:"driver" type:"string"`

	DriverOpts map[string]*string `locationName:"driverOpts" type:"map"`

	Labels map[string]*string `locationName:"labels" type:"map"`

	Scope *string `locationName:"scope" type:"string" enum:"Scope"`
}

// String returns the string representation
func (s DockerVolumeConfiguration) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s DockerVolumeConfiguration) GoString() string {
	return s.String()
}

type ECRAuthData struct {
	_ struct{} `type:"structure"`

	EndpointOverride *string `locationName:"endpointOverride" type:"string"`

	Region *string `locationName:"region" type:"string"`

	RegistryId *string `locationName:"registryId" type:"string"`

	UseExecutionRole *bool `locationName:"useExecutionRole" type:"boolean"`
}

// String returns the string representation
func (s ECRAuthData) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ECRAuthData) GoString() string {
	return s.String()
}

type ElasticNetworkInterface struct {
	_ struct{} `type:"structure"`

	AttachmentArn *string `locationName:"attachmentArn" type:"string"`

	DomainName []*string `locationName:"domainName" type:"list"`

	DomainNameServers []*string `locationName:"domainNameServers" type:"list"`

	Ec2Id *string `locationName:"ec2Id" type:"string"`

	InterfaceAssociationProtocol *string `locationName:"interfaceAssociationProtocol" type:"string" enum:"NetworkInterfaceAssociationProtocol"`

	InterfaceVlanProperties *NetworkInterfaceVlanProperties `locationName:"interfaceVlanProperties" type:"structure"`

	Ipv4Addresses []*IPv4AddressAssignment `locationName:"ipv4Addresses" type:"list"`

	Ipv6Addresses []*IPv6AddressAssignment `locationName:"ipv6Addresses" type:"list"`

	MacAddress *string `locationName:"macAddress" type:"string"`

	PrivateDnsName *string `locationName:"privateDnsName" type:"string"`

	SubnetGatewayIpv4Address *string `locationName:"subnetGatewayIpv4Address" type:"string"`
}

// String returns the string representation
func (s ElasticNetworkInterface) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ElasticNetworkInterface) GoString() string {
	return s.String()
}

type EncodedString struct {
	_ struct{} `type:"structure"`

	Encoding *string `locationName:"encoding" type:"string" enum:"Encoding"`

	Value *string `locationName:"value" type:"string"`
}

// String returns the string representation
func (s EncodedString) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s EncodedString) GoString() string {
	return s.String()
}

type ErrorInput struct {
	_ struct{} `type:"structure"`

	Message *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s ErrorInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ErrorInput) GoString() string {
	return s.String()
}

type ErrorMessage struct {
	_ struct{} `type:"structure"`

	Message *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s ErrorMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ErrorMessage) GoString() string {
	return s.String()
}

type ErrorOutput struct {
	_ struct{} `type:"structure"`
}

// String returns the string representation
func (s ErrorOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ErrorOutput) GoString() string {
	return s.String()
}

type HeartbeatInput struct {
	_ struct{} `type:"structure"`

	Healthy *bool `locationName:"healthy" type:"boolean"`
}

// String returns the string representation
func (s HeartbeatInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s HeartbeatInput) GoString() string {
	return s.String()
}

type HeartbeatMessage struct {
	_ struct{} `type:"structure"`

	Healthy *bool `locationName:"healthy" type:"boolean"`
}

// String returns the string representation
func (s HeartbeatMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s HeartbeatMessage) GoString() string {
	return s.String()
}

type HeartbeatOutput struct {
	_ struct{} `type:"structure"`
}

// String returns the string representation
func (s HeartbeatOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s HeartbeatOutput) GoString() string {
	return s.String()
}

type HostVolumeProperties struct {
	_ struct{} `type:"structure"`

	SourcePath *string `locationName:"sourcePath" type:"string"`
}

// String returns the string representation
func (s HostVolumeProperties) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s HostVolumeProperties) GoString() string {
	return s.String()
}

type IAMRoleCredentials struct {
	_ struct{} `type:"structure"`

	AccessKeyId *string `locationName:"accessKeyId" type:"string"`

	CredentialsId *string `locationName:"credentialsId" type:"string"`

	Expiration *string `locationName:"expiration" type:"string"`

	RoleArn *string `locationName:"roleArn" type:"string"`

	SecretAccessKey *string `locationName:"secretAccessKey" type:"string"`

	SessionToken *string `locationName:"sessionToken" type:"string"`
}

// String returns the string representation
func (s IAMRoleCredentials) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s IAMRoleCredentials) GoString() string {
	return s.String()
}

type IAMRoleCredentialsAckRequest struct {
	_ struct{} `type:"structure"`

	CredentialsId *string `locationName:"credentialsId" type:"string"`

	Expiration *string `locationName:"expiration" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s IAMRoleCredentialsAckRequest) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s IAMRoleCredentialsAckRequest) GoString() string {
	return s.String()
}

type IAMRoleCredentialsMessage struct {
	_ struct{} `type:"structure"`

	MessageId *string `locationName:"messageId" type:"string"`

	RoleCredentials *IAMRoleCredentials `locationName:"roleCredentials" type:"structure"`

	RoleType *string `locationName:"roleType" type:"string" enum:"RoleType"`

	TaskArn *string `locationName:"taskArn" type:"string"`
}

// String returns the string representation
func (s IAMRoleCredentialsMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s IAMRoleCredentialsMessage) GoString() string {
	return s.String()
}

type IPv4AddressAssignment struct {
	_ struct{} `type:"structure"`

	Primary *bool `locationName:"primary" type:"boolean"`

	PrivateAddress *string `locationName:"privateAddress" type:"string"`
}

// String returns the string representation
func (s IPv4AddressAssignment) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s IPv4AddressAssignment) GoString() string {
	return s.String()
}

type IPv6AddressAssignment struct {
	_ struct{} `type:"structure"`

	Address *string `locationName:"address" type:"string"`
}

// String returns the string representation
func (s IPv6AddressAssignment) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s IPv6AddressAssignment) GoString() string {
	return s.String()
}

type InactiveInstanceException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s InactiveInstanceException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s InactiveInstanceException) GoString() string {
	return s.String()
}

type InvalidClusterException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s InvalidClusterException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s InvalidClusterException) GoString() string {
	return s.String()
}

type InvalidInstanceException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s InvalidInstanceException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s InvalidInstanceException) GoString() string {
	return s.String()
}

type MountPoint struct {
	_ struct{} `type:"structure"`

	ContainerPath *string `locationName:"containerPath" type:"string"`

	ReadOnly *bool `locationName:"readOnly" type:"boolean"`

	SourceVolume *string `locationName:"sourceVolume" type:"string"`
}

// String returns the string representation
func (s MountPoint) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s MountPoint) GoString() string {
	return s.String()
}

type NackRequest struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	Reason *string `locationName:"reason" type:"string"`
}

// String returns the string representation
func (s NackRequest) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s NackRequest) GoString() string {
	return s.String()
}

type NetworkInterfaceVlanProperties struct {
	_ struct{} `type:"structure"`

	TrunkInterfaceMacAddress *string `locationName:"trunkInterfaceMacAddress" type:"string"`

	VlanId *string `locationName:"vlanId" type:"string"`
}

// String returns the string representation
func (s NetworkInterfaceVlanProperties) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s NetworkInterfaceVlanProperties) GoString() string {
	return s.String()
}

type PayloadInput struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	SeqNum *int64 `locationName:"seqNum" type:"integer"`

	Tasks []*Task `locationName:"tasks" type:"list"`
}

// String returns the string representation
func (s PayloadInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PayloadInput) GoString() string {
	return s.String()
}

type PayloadMessage struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	GeneratedAt *int64 `locationName:"generatedAt" type:"long"`

	MessageId *string `locationName:"messageId" type:"string"`

	SeqNum *int64 `locationName:"seqNum" type:"integer"`

	Tasks []*Task `locationName:"tasks" type:"list"`
}

// String returns the string representation
func (s PayloadMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PayloadMessage) GoString() string {
	return s.String()
}

type PayloadOutput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s PayloadOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PayloadOutput) GoString() string {
	return s.String()
}

type PerformUpdateInput struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	UpdateInfo *UpdateInfo `locationName:"updateInfo" type:"structure"`
}

// String returns the string representation
func (s PerformUpdateInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PerformUpdateInput) GoString() string {
	return s.String()
}

type PerformUpdateMessage struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	UpdateInfo *UpdateInfo `locationName:"updateInfo" type:"structure"`
}

// String returns the string representation
func (s PerformUpdateMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PerformUpdateMessage) GoString() string {
	return s.String()
}

type PerformUpdateOutput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s PerformUpdateOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PerformUpdateOutput) GoString() string {
	return s.String()
}

type PollInput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	SendCredentials *bool `locationName:"sendCredentials" type:"boolean"`

	SeqNum *int64 `locationName:"seqNum" type:"integer"`

	VersionInfo *VersionInfo `locationName:"versionInfo" type:"structure"`
}

// String returns the string representation
func (s PollInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PollInput) GoString() string {
	return s.String()
}

type PollOutput struct {
	_ struct{} `type:"structure"`

	Message *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s PollOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PollOutput) GoString() string {
	return s.String()
}

type PollRequest struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	SendCredentials *bool `locationName:"sendCredentials" type:"boolean"`

	SeqNum *int64 `locationName:"seqNum" type:"integer"`

	VersionInfo *VersionInfo `locationName:"versionInfo" type:"structure"`
}

// String returns the string representation
func (s PollRequest) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PollRequest) GoString() string {
	return s.String()
}

type PortMapping struct {
	_ struct{} `type:"structure"`

	ContainerPort *int64 `locationName:"containerPort" type:"integer"`

	HostPort *int64 `locationName:"hostPort" type:"integer"`

	Protocol *string `locationName:"protocol" type:"string" enum:"TransportProtocol"`
}

// String returns the string representation
func (s PortMapping) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s PortMapping) GoString() string {
	return s.String()
}

type ProxyConfiguration struct {
	_ struct{} `type:"structure"`

	ContainerName *string `locationName:"containerName" type:"string"`

	Properties map[string]*string `locationName:"properties" type:"map"`

	Type *string `locationName:"type" type:"string" enum:"ProxyConfigurationType"`
}

// String returns the string representation
func (s ProxyConfiguration) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ProxyConfiguration) GoString() string {
	return s.String()
}

type RefreshTaskIAMRoleCredentialsInput struct {
	_ struct{} `type:"structure"`

	MessageId *string `locationName:"messageId" type:"string"`

	RoleCredentials *IAMRoleCredentials `locationName:"roleCredentials" type:"structure"`

	RoleType *string `locationName:"roleType" type:"string" enum:"RoleType"`

	TaskArn *string `locationName:"taskArn" type:"string"`
}

// String returns the string representation
func (s RefreshTaskIAMRoleCredentialsInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s RefreshTaskIAMRoleCredentialsInput) GoString() string {
	return s.String()
}

type RefreshTaskIAMRoleCredentialsOutput struct {
	_ struct{} `type:"structure"`

	CredentialsId *string `locationName:"credentialsId" type:"string"`

	Expiration *string `locationName:"expiration" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s RefreshTaskIAMRoleCredentialsOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s RefreshTaskIAMRoleCredentialsOutput) GoString() string {
	return s.String()
}

type RegistryAuthenticationData struct {
	_ struct{} `type:"structure"`

	AsmAuthData *ASMAuthData `locationName:"asmAuthData" type:"structure"`

	EcrAuthData *ECRAuthData `locationName:"ecrAuthData" type:"structure"`

	Type *string `locationName:"type" type:"string" enum:"AuthenticationType"`
}

// String returns the string representation
func (s RegistryAuthenticationData) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s RegistryAuthenticationData) GoString() string {
	return s.String()
}

type Secret struct {
	_ struct{} `type:"structure"`

	ContainerPath *string `locationName:"containerPath" type:"string"`

	Name *string `locationName:"name" type:"string"`

	Provider *string `locationName:"provider" type:"string" enum:"SecretProvider"`

	Region *string `locationName:"region" type:"string"`

	Type *string `locationName:"type" type:"string" enum:"SecretType"`

	ValueFrom *string `locationName:"valueFrom" type:"string"`
}

// String returns the string representation
func (s Secret) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s Secret) GoString() string {
	return s.String()
}

type ServerException struct {
	_ struct{} `type:"structure"`

	Message_ *string `locationName:"message" type:"string"`
}

// String returns the string representation
func (s ServerException) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s ServerException) GoString() string {
	return s.String()
}

type StageUpdateInput struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	UpdateInfo *UpdateInfo `locationName:"updateInfo" type:"structure"`
}

// String returns the string representation
func (s StageUpdateInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s StageUpdateInput) GoString() string {
	return s.String()
}

type StageUpdateMessage struct {
	_ struct{} `type:"structure"`

	ClusterArn *string `locationName:"clusterArn" type:"string"`

	ContainerInstanceArn *string `locationName:"containerInstanceArn" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	UpdateInfo *UpdateInfo `locationName:"updateInfo" type:"structure"`
}

// String returns the string representation
func (s StageUpdateMessage) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s StageUpdateMessage) GoString() string {
	return s.String()
}

type StageUpdateOutput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`
}

// String returns the string representation
func (s StageUpdateOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s StageUpdateOutput) GoString() string {
	return s.String()
}

type Task struct {
	_ struct{} `type:"structure"`

	Arn *string `locationName:"arn" type:"string"`

	Associations []*Association `locationName:"associations" type:"list"`

	Containers []*Container `locationName:"containers" type:"list"`

	Cpu *float64 `locationName:"cpu" type:"double"`

	DesiredStatus *string `locationName:"desiredStatus" type:"string"`

	ElasticNetworkInterfaces []*ElasticNetworkInterface `locationName:"elasticNetworkInterfaces" type:"list"`

	ExecutionRoleCredentials *IAMRoleCredentials `locationName:"executionRoleCredentials" type:"structure"`

	Family *string `locationName:"family" type:"string"`

	IpcMode *string `locationName:"ipcMode" type:"string"`

	Memory *int64 `locationName:"memory" type:"integer"`

	Overrides *string `locationName:"overrides" type:"string"`

	PidMode *string `locationName:"pidMode" type:"string"`

	ProxyConfiguration *ProxyConfiguration `locationName:"proxyConfiguration" type:"structure"`

	RoleCredentials *IAMRoleCredentials `locationName:"roleCredentials" type:"structure"`

	TaskDefinitionAccountId *string `locationName:"taskDefinitionAccountId" type:"string"`

	Version *string `locationName:"version" type:"string"`

	Volumes []*Volume `locationName:"volumes" type:"list"`
}

// String returns the string representation
func (s Task) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s Task) GoString() string {
	return s.String()
}

type UpdateFailureInput struct {
	_ struct{} `type:"structure"`

	Cluster *string `locationName:"cluster" type:"string"`

	ContainerInstance *string `locationName:"containerInstance" type:"string"`

	MessageId *string `locationName:"messageId" type:"string"`

	Reason *string `locationName:"reason" type:"string"`
}

// String returns the string representation
func (s UpdateFailureInput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s UpdateFailureInput) GoString() string {
	return s.String()
}

type UpdateFailureOutput struct {
	_ struct{} `type:"structure"`
}

// String returns the string representation
func (s UpdateFailureOutput) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s UpdateFailureOutput) GoString() string {
	return s.String()
}

type UpdateInfo struct {
	_ struct{} `type:"structure"`

	Location *string `locationName:"location" type:"string"`

	Signature *string `locationName:"signature" type:"string"`
}

// String returns the string representation
func (s UpdateInfo) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s UpdateInfo) GoString() string {
	return s.String()
}

type VersionInfo struct {
	_ struct{} `type:"structure"`

	AgentHash *string `locationName:"agentHash" type:"string"`

	AgentVersion *string `locationName:"agentVersion" type:"string"`

	DockerVersion *string `locationName:"dockerVersion" type:"string"`
}

// String returns the string representation
func (s VersionInfo) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s VersionInfo) GoString() string {
	return s.String()
}

type Volume struct {
	_ struct{} `type:"structure"`

	DockerVolumeConfiguration *DockerVolumeConfiguration `locationName:"dockerVolumeConfiguration" type:"structure"`

	Host *HostVolumeProperties `locationName:"host" type:"structure"`

	Name *string `locationName:"name" type:"string"`

	Type *string `locationName:"type" type:"string" enum:"VolumeType"`
}

// String returns the string representation
func (s Volume) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s Volume) GoString() string {
	return s.String()
}

type VolumeFrom struct {
	_ struct{} `type:"structure"`

	ReadOnly *bool `locationName:"readOnly" type:"boolean"`

	SourceContainer *string `locationName:"sourceContainer" type:"string"`
}

// String returns the string representation
func (s VolumeFrom) String() string {
	return awsutil.Prettify(s)
}

// GoString returns the string representation
func (s VolumeFrom) GoString() string {
	return s.String()
}
