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

package podman

import (
	"context"
	"fmt"

	"io"
	"os"
	"strings"
	"time"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apicontainerstatus "github.com/aws/amazon-ecs-agent/agent/api/container/status"
	apierrors "github.com/aws/amazon-ecs-agent/agent/api/errors"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/dockerclient"
	. "github.com/aws/amazon-ecs-agent/agent/dockerclient/dockerapi"
	"github.com/aws/amazon-ecs-agent/agent/utils/retry"

	"github.com/cihub/seelog"
	"github.com/containers/podman/v2/pkg/bindings"
	"github.com/containers/podman/v2/pkg/bindings/containers"
	"github.com/containers/podman/v2/pkg/bindings/images"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/containers/podman/v2/pkg/specgen"
	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
)

var ctxTimeoutStopContainer = dockerclient.StopContainerTimeout

type inactivityTimeoutHandlerFunc func(reader io.ReadCloser, timeout time.Duration, cancelRequest func(), canceled *uint32) (io.ReadCloser, chan<- struct{})

// podmanClient implements the DockerClient interface
type podmanClient struct {
	ctx              context.Context
	version          dockerclient.DockerVersion
	imagePullBackoff retry.Backoff
}

type ImagePullResponsePodman struct {
	Id             string `json:"id,omitempty"`
	Status         string `json:"status,omitempty"`
	ProgressDetail struct {
		Current int64 `json:"current,omitempty"`
		Total   int64 `json:"total,omitempty"`
	} `json:"progressDetail,omitempty"`
	Progress string `json:"progress,omitempty"`
	Error    string `json:"error,omitempty"`
}

// NewPodmanDockerClient creates a new DockerClient implemented with Podman runtime.
func NewPodmanDockerClient(cfg *config.Config, ctx context.Context) (DockerClient, error) {
	// Get Podman socket location
	sock_dir := os.Getenv("XDG_RUNTIME_DIR")
	socket := "unix:" + sock_dir

	// Connect to Podman socket
	connText, err := bindings.NewConnection(context.Background(), socket)
	if err != nil {
		return nil, err
	}

	return &podmanClient{ctx: connText}, nil
}

func (pm *podmanClient) SupportedVersions() []dockerclient.DockerVersion {
	return []dockerclient.DockerVersion{
		dockerclient.Version_2_2,
	}
}

func (pm *podmanClient) KnownVersions() []dockerclient.DockerVersion {
	return []dockerclient.DockerVersion{
		dockerclient.Version_2_2,
	}
}

func (pm *podmanClient) WithVersion(dockerclient.DockerVersion) DockerClient {
	if pm.ctx != nil {
		return pm
	}
	sock_dir := os.Getenv("XDG_RUNTIME_DIR")
	socket := "unix:" + sock_dir

	// Connect to Podman socket
	connText, _ := bindings.NewConnection(context.Background(), socket)

	return &podmanClient{ctx: connText}

}

func (pm *podmanClient) ContainerEvents(context.Context) (<-chan DockerContainerChangeEvent, error) {
	return nil, errors.New("not implemented")
}

func (pm *podmanClient) pullImage(ctx context.Context, image string,
	authData *apicontainer.RegistryAuthenticationData) apierrors.NamedError {
	seelog.Debugf("DockerGoClient: pulling image: %s", image)
	_, err := images.Pull(ctx, image, entities.ImagePullOptions{})
	if err != nil {
		fmt.Println(err)
		return WrapPullErrorAsNamedError(err)
	}
	return nil
}

func (pm *podmanClient) PullImage(ctx context.Context, image string, authData *apicontainer.RegistryAuthenticationData,
	timeout time.Duration) DockerContainerMetadata {

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response := make(chan DockerContainerMetadata, 1)
	go func() {
		err := retry.RetryNWithBackoffCtx(ctx, pm.imagePullBackoff, 5,
			func() error {
				err := pm.pullImage(ctx, image, authData)
				if err != nil {
					seelog.Errorf("DockerGoClient: failed to pull image %s: [%s] %s", image, err.ErrorName(), err.Error())
				}
				return err
			})
		response <- DockerContainerMetadata{Error: WrapPullErrorAsNamedError(err)}
	}()

	select {
	case resp := <-response:
		return resp
	case <-ctx.Done():
		// Context has either expired or canceled. If it has timed out,
		// send back the DockerTimeoutError
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			return DockerContainerMetadata{Error: &DockerTimeoutError{timeout, "pulled"}}
		}
		// Context was canceled even though there was no timeout. Send
		// back an error.
		return DockerContainerMetadata{Error: &CannotPullContainerError{err}}
	}
}

func (pm *podmanClient) containerMetadata(ctx context.Context, id string) DockerContainerMetadata {
	ctx, cancel := context.WithTimeout(ctx, dockerclient.InspectContainerTimeout)
	defer cancel()
	dockerContainer, err := pm.InspectContainer(ctx, id, dockerclient.InspectContainerTimeout)
	if err != nil {
		return DockerContainerMetadata{DockerID: id, Error: CannotInspectContainerError{err}}
	}
	return MetadataFromContainer(dockerContainer)
}

func (pm *podmanClient) createContainer(ctx context.Context, config *dockercontainer.Config, hostConfig *dockercontainer.HostConfig,
	name string) DockerContainerMetadata {

	s := specgen.NewSpecGenerator(config.Image, false)
	s.Terminal = true
	r, err := containers.CreateWithSpec(ctx, s)
	if err != nil {
		return DockerContainerMetadata{Error: WrapPullErrorAsNamedError(err)}
	}
	return pm.containerMetadata(ctx, r.ID)
}

func (pm *podmanClient) CreateContainer(ctx context.Context,
	config *dockercontainer.Config, hostConfig *dockercontainer.HostConfig, name string,
	timeout time.Duration) DockerContainerMetadata {

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Buffered channel so in the case of timeout it takes one write, never gets
	// read, and can still be GC'd
	response := make(chan DockerContainerMetadata, 1)
	go func() { response <- pm.createContainer(ctx, config, hostConfig, name) }()

	// Wait until we get a response or for the 'done' context channel
	select {
	case resp := <-response:
		return resp
	case <-ctx.Done():
		// Context has either expired or canceled. If it has timed out,
		// send back the DockerTimeoutError
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			return DockerContainerMetadata{Error: &DockerTimeoutError{timeout, "created"}}
		}
		// Context was canceled even though there was no timeout. Send
		// back an error.
		return DockerContainerMetadata{Error: &CannotCreateContainerError{err}}
	}

}

func (pm *podmanClient) startContainer(ctx context.Context, id string) DockerContainerMetadata {
	err := containers.Start(ctx, id, nil)
	if err != nil {
		return DockerContainerMetadata{Error: CannotGetDockerClientError{Version: pm.version, Err: err}}
	}
	metadata := pm.containerMetadata(ctx, id)

	return metadata
}

func (pm *podmanClient) StartContainer(ctx context.Context, id string, timeout time.Duration) DockerContainerMetadata {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Buffered channel so in the case of timeout it takes one write, never gets
	// read, and can still be GC'd
	response := make(chan DockerContainerMetadata, 1)
	go func() { response <- pm.startContainer(ctx, id) }()
	select {
	case resp := <-response:
		return resp
	case <-ctx.Done():
		// Context has either expired or canceled. If it has timed out,
		// send back the DockerTimeoutError
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			return DockerContainerMetadata{Error: &DockerTimeoutError{timeout, "started"}}
		}
		return DockerContainerMetadata{Error: CannotStartContainerError{err}}
	}
}

func (pm *podmanClient) stopContainer(ctx context.Context, dockerID string, timeout time.Duration) DockerContainerMetadata {
	err := containers.Stop(ctx, dockerID, nil)
	metadata := pm.containerMetadata(ctx, dockerID)
	if err != nil {
		seelog.Errorf("DockerGoClient: error stopping container ID=%s: %v", dockerID, err)
		if metadata.Error == nil {
			if strings.Contains(err.Error(), "No such container") {
				err = NoSuchContainerError{dockerID}
			}
			metadata.Error = CannotStopContainerError{err}
		}
	}
	return metadata
}

func (pm *podmanClient) StopContainer(ctx context.Context, dockerID string, timeout time.Duration) DockerContainerMetadata {
	// ctxTimeout is sum of timeout(applied to the StopContainer api call) and a fixed constant dockerclient.StopContainerTimeout
	// the context's timeout should be greater than the sigkill timout for the StopContainer call
	ctxTimeout := timeout + ctxTimeoutStopContainer
	ctx, cancel := context.WithTimeout(ctx, ctxTimeout)
	defer cancel()
	// Buffered channel so in the case of timeout it takes one write, never gets
	// read, and can still be GC'd
	response := make(chan DockerContainerMetadata, 1)
	go func() { response <- pm.stopContainer(ctx, dockerID, timeout) }()
	select {
	case resp := <-response:
		return resp
	case <-ctx.Done():
		// Context has either expired or canceled. If it has timed out,
		// send back the DockerTimeoutError
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			return DockerContainerMetadata{Error: &DockerTimeoutError{ctxTimeout, "stopped"}}
		}
		return DockerContainerMetadata{Error: CannotStopContainerError{err}}
	}

}

func (pm *podmanClient) DescribeContainer(ctx context.Context, dockerID string) (apicontainerstatus.ContainerStatus,
	DockerContainerMetadata) {
	dockerContainer, err := pm.InspectContainer(ctx, dockerID, dockerclient.InspectContainerTimeout)
	if err != nil {
		return apicontainerstatus.ContainerStatusNone, DockerContainerMetadata{Error: CannotDescribeContainerError{err}}
	}
	return DockerStateToState(dockerContainer.ContainerJSONBase.State), MetadataFromContainer(dockerContainer)

}

// TODO: implementation.
func (pm *podmanClient) RemoveContainer(context.Context, string, time.Duration) error {
	return errors.New("not implemented")
}

func (pm *podmanClient) inspectContainer(ctx context.Context, dockerID string) (*types.ContainerJSON, error) {
	ctrData, err := containers.Inspect(ctx, dockerID, nil)

	healthCheck := &types.Health{
		Status:        ctrData.State.Healthcheck.Status,
		FailingStreak: ctrData.State.Healthcheck.FailingStreak,
		Log:           nil,
	}

	inspectState := &types.ContainerState{
		Status:     ctrData.State.Status,
		Running:    ctrData.State.Running,
		Paused:     ctrData.State.Paused,
		Restarting: ctrData.State.Restarting,
		OOMKilled:  ctrData.State.OOMKilled,
		Dead:       ctrData.State.Dead,
		Pid:        ctrData.State.Pid,
		ExitCode:   int(ctrData.State.ExitCode),
		Error:      ctrData.State.Error,
		StartedAt:  ctrData.State.StartedAt.String(),
		FinishedAt: ctrData.State.FinishedAt.String(),
		Health:     healthCheck,
	}

	init := new(bool)
	*init = ctrData.HostConfig.Init

	hostConfig := &dockercontainer.HostConfig{
		Binds:           ctrData.HostConfig.Binds,
		ContainerIDFile: ctrData.HostConfig.ContainerIDFile,
		LogConfig:       dockercontainer.LogConfig{},
		NetworkMode:     dockercontainer.NetworkMode(ctrData.HostConfig.NetworkMode),
		AutoRemove:      ctrData.HostConfig.AutoRemove,
		VolumeDriver:    ctrData.HostConfig.VolumeDriver,
		VolumesFrom:     ctrData.HostConfig.VolumesFrom,
		CapAdd:          ctrData.HostConfig.CapAdd,
		CapDrop:         ctrData.HostConfig.CapDrop,
		DNS:             ctrData.HostConfig.Dns,
		DNSOptions:      ctrData.HostConfig.DnsOptions,
		DNSSearch:       ctrData.HostConfig.DnsSearch,
		ExtraHosts:      ctrData.HostConfig.ExtraHosts,
		GroupAdd:        ctrData.HostConfig.GroupAdd,
		Cgroup:          dockercontainer.CgroupSpec(ctrData.HostConfig.Cgroup),
		Links:           ctrData.HostConfig.Links,
		OomScoreAdj:     ctrData.HostConfig.OomScoreAdj,
		PidMode:         dockercontainer.PidMode(ctrData.HostConfig.PidMode),
		Privileged:      ctrData.HostConfig.Privileged,
		PublishAllPorts: ctrData.HostConfig.PublishAllPorts,
		ReadonlyRootfs:  ctrData.HostConfig.ReadonlyRootfs,
		SecurityOpt:     ctrData.HostConfig.SecurityOpt,
		Tmpfs:           ctrData.HostConfig.Tmpfs,
		UTSMode:         dockercontainer.UTSMode(ctrData.HostConfig.UTSMode),
		UsernsMode:      dockercontainer.UsernsMode(ctrData.HostConfig.UsernsMode),
		ShmSize:         ctrData.HostConfig.ShmSize,
		Runtime:         ctrData.HostConfig.Runtime,
		Isolation:       "",
		Resources:       dockercontainer.Resources{},
		Init:            init,
	}

	containerJSONBase := &types.ContainerJSONBase{
		ID:              ctrData.ID,
		Created:         ctrData.Created.String(),
		Path:            ctrData.Path,
		Args:            []string{ctrData.Path},
		State:           inspectState,
		Image:           ctrData.Image,
		ResolvConfPath:  ctrData.ResolvConfPath,
		HostnamePath:    ctrData.HostnamePath,
		HostsPath:       ctrData.HostsPath,
		LogPath:         ctrData.LogPath,
		Node:            nil,
		Name:            ctrData.Name,
		RestartCount:    int(ctrData.RestartCount),
		Driver:          ctrData.Driver,
		Platform:        "",
		MountLabel:      ctrData.MountLabel,
		ProcessLabel:    ctrData.ProcessLabel,
		AppArmorProfile: ctrData.AppArmorProfile,
		ExecIDs:         ctrData.ExecIDs,
		HostConfig:      hostConfig,
		GraphDriver:     types.GraphDriverData{},
		SizeRw:          ctrData.SizeRw,
	}

	var natPortMap = nat.PortMap{}
	for key, value := range ctrData.NetworkSettings.Ports {
		var inspectHostPort []nat.PortBinding
		for _, portBind := range value {
			inspectHostPortSingle := nat.PortBinding{
				HostIP:   portBind.HostIP,
				HostPort: portBind.HostPort,
			}
			inspectHostPort = append(inspectHostPort, inspectHostPortSingle)
		}
		natPortMap[nat.Port(key)] = inspectHostPort
	}

	networkSettingbase := types.NetworkSettingsBase{
		Bridge:                 ctrData.NetworkSettings.Bridge,
		SandboxID:              ctrData.NetworkSettings.SandboxID,
		HairpinMode:            ctrData.NetworkSettings.HairpinMode,
		LinkLocalIPv6Address:   ctrData.NetworkSettings.LinkLocalIPv6Address,
		LinkLocalIPv6PrefixLen: ctrData.NetworkSettings.LinkLocalIPv6PrefixLen,
		Ports:                  natPortMap,
		SandboxKey:             ctrData.NetworkSettings.SandboxKey,
	}

	defaultNetworkSetting := types.DefaultNetworkSettings{
		EndpointID:          ctrData.NetworkSettings.EndpointID,
		Gateway:             ctrData.NetworkSettings.Gateway,
		GlobalIPv6Address:   ctrData.NetworkSettings.GlobalIPv6Address,
		GlobalIPv6PrefixLen: ctrData.NetworkSettings.GlobalIPv6PrefixLen,
		IPAddress:           ctrData.NetworkSettings.IPAddress,
		IPPrefixLen:         ctrData.NetworkSettings.IPPrefixLen,
		IPv6Gateway:         ctrData.NetworkSettings.IPv6Gateway,
		MacAddress:          ctrData.NetworkSettings.MacAddress,
	}

	networkSetting := &types.NetworkSettings{
		NetworkSettingsBase:    networkSettingbase,
		DefaultNetworkSettings: defaultNetworkSetting,
	}

	strSlice := strslice.StrSlice{ctrData.Config.Entrypoint}
	containerConfig := &dockercontainer.Config{
		Hostname:     ctrData.Config.Hostname,
		AttachStdin:  ctrData.Config.AttachStdin,
		AttachStdout: ctrData.Config.AttachStdout,
		AttachStderr: ctrData.Config.AttachStderr,
		Tty:          ctrData.Config.Tty,
		OpenStdin:    ctrData.Config.OpenStdin,
		StdinOnce:    ctrData.Config.StdinOnce,
		Env:          ctrData.Config.Env,
		Cmd:          ctrData.Config.Cmd,
		// TODO: fix type mismatch
		//Healthcheck:  ctrData.Config.Healthcheck,
		Image:        ctrData.Config.Image,
		Volumes:      ctrData.Config.Volumes,
		WorkingDir:   ctrData.Config.WorkingDir,
		Entrypoint:   strSlice,
	}

	containerJson := &types.ContainerJSON{
		ContainerJSONBase: containerJSONBase,
		Config:            containerConfig,
		NetworkSettings:   networkSetting,
	}
	return containerJson, err
}

func (pm *podmanClient) InspectContainer(ctx context.Context, dockerID string, timeout time.Duration) (*types.ContainerJSON, error) {
	type inspectResponse struct {
		container *types.ContainerJSON
		err       error
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Buffered channel so in the case of timeout it takes one write, never gets
	// read, and can still be GC'd
	response := make(chan inspectResponse, 1)
	go func() {
		container, err := pm.inspectContainer(ctx, dockerID)
		response <- inspectResponse{container, err}
	}()

	// Wait until we get a response or for the 'done' context channel
	select {
	case resp := <-response:
		return resp.container, resp.err
	case <-ctx.Done():
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			return nil, &DockerTimeoutError{timeout, "inspecting"}
		}

		return nil, &CannotInspectContainerError{err}
	}
}

func (pm *podmanClient) ListContainers(ctx context.Context, all bool, timeout time.Duration) ListContainersResponse {
	var latestContainers = 1
	containerLatestList, err := containers.List(ctx, nil, nil, &latestContainers, nil, nil, nil)
	if err != nil {
		return ListContainersResponse{Error: &CannotListContainersError{err}}
	}

	var listContainerResponse ListContainersResponse
	var dockerIds []string

	for _, containerList := range containerLatestList {
		dockerIds = append(dockerIds, containerList.ID)
	}
	listContainerResponse.DockerIDs = dockerIds
	return listContainerResponse
}

func (pm *podmanClient) ListImages(ctx context.Context, timeout time.Duration) ListImagesResponse {
	imageSummary, err := images.List(ctx, nil, nil)
	if err != nil {
		return ListImagesResponse{Error: &CannotListImagesError{err}}
	}

	var listImageResponses ListImagesResponse
	var imageIds []string
	var repoTags []string

	for _, imageResponse := range imageSummary {
		imageIds = append(imageIds, imageResponse.ID)
		repoTags = append(repoTags, imageResponse.RepoTags[0])
	}
	listImageResponses.RepoTags = repoTags
	listImageResponses.ImageIDs = imageIds

	return listImageResponses
}

// TODO: implementation.
func (pm *podmanClient) CreateVolume(context.Context, string, string, map[string]string, map[string]string, time.Duration) SDKVolumeResponse {
	return SDKVolumeResponse{}
}

// TODO: implementation.
func (pm *podmanClient) InspectVolume(context.Context, string, time.Duration) SDKVolumeResponse {
	return SDKVolumeResponse{}
}

// TODO: implementation.
func (pm *podmanClient) RemoveVolume(context.Context, string, time.Duration) error {
	return errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) ListPluginsWithFilters(context.Context, bool, []string, time.Duration) ([]string, error) {
	return nil, errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) ListPlugins(context.Context, time.Duration, filters.Args) ListPluginsResponse {
	return ListPluginsResponse{}
}

// TODO: implementation.
func (pm *podmanClient) Stats(context.Context, string, time.Duration) (<-chan *types.StatsJSON, <-chan error) {
	return nil, nil
}

// TODO: implementation.
func (pm *podmanClient) Version(context.Context, time.Duration) (string, error) {
	return "", errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) APIVersion() (dockerclient.DockerVersion, error) {
	return dockerclient.Version_1_17, errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) InspectImage(string) (*types.ImageInspect, error) {
	return nil, errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) RemoveImage(context.Context, string, time.Duration) error {
	return errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) LoadImage(context.Context, io.Reader, time.Duration) error {
	return errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) Info(context.Context, time.Duration) (types.Info, error) {
	return types.Info{}, errors.New("not implemented")
}
