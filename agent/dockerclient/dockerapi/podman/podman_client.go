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
	"io"
	"os"
	"time"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apicontainerstatus "github.com/aws/amazon-ecs-agent/agent/api/container/status"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/dockerclient"
	. "github.com/aws/amazon-ecs-agent/agent/dockerclient/dockerapi"

	"github.com/cihub/seelog"
	"github.com/containers/podman/v2/pkg/bindings"
	"github.com/containers/podman/v2/pkg/bindings/containers"
	"github.com/containers/podman/v2/pkg/bindings/images"
	"github.com/containers/podman/v2/pkg/bindings/system"
	"github.com/containers/podman/v2/pkg/bindings/volumes"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/pkg/errors"
)

// podmanClient implements the DockerClient interface
type podmanClient struct {
	ctx context.Context
}

// NewPodmanDockerClient creates a new DockerClient implemented with Podman runtime.
func NewPodmanDockerClient(cfg *config.Config, ctx context.Context) (DockerClient, error) {
	socket := os.Getenv("ECS_PODMAN_SOCKET")
	ctx, err := bindings.NewConnection(ctx, socket)
	if err != nil {
		return nil, err
	}
	return &podmanClient{
		ctx: ctx,
	}, nil
}

// TODO: implementation.
func (pm *podmanClient) SupportedVersions() []dockerclient.DockerVersion {
	return nil
}

// TODO: implementation.
func (pm *podmanClient) KnownVersions() []dockerclient.DockerVersion {
	return nil
}

// TODO: implementation.
func (pm *podmanClient) WithVersion(dockerclient.DockerVersion) DockerClient {
	return &podmanClient{}
}

// TODO: implementation.
func (pm *podmanClient) ContainerEvents(context.Context) (<-chan DockerContainerChangeEvent, error) {
	return nil, errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) PullImage(context.Context, string, *apicontainer.RegistryAuthenticationData, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{}
}

// TODO: implementation.
func (pm *podmanClient) CreateContainer(context.Context, *dockercontainer.Config, *dockercontainer.HostConfig, string, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{}
}

// TODO: implementation.
func (pm *podmanClient) StartContainer(context.Context, string, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{}
}

// TODO: implementation.
func (pm *podmanClient) StopContainer(context.Context, string, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{}
}

// TODO: implementation.
func (pm *podmanClient) DescribeContainer(context.Context, string) (apicontainerstatus.ContainerStatus, DockerContainerMetadata) {
	return apicontainerstatus.ContainerStatusNone, DockerContainerMetadata{}
}

// TODO: implementation.
func (pm *podmanClient) RemoveContainer(context.Context, string, time.Duration) error {
	return errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) InspectContainer(context.Context, string, time.Duration) (*types.ContainerJSON, error) {
	return nil, errors.New("not implemented")
}

// TODO: implementation.
func (pm *podmanClient) ListContainers(context.Context, bool, time.Duration) ListContainersResponse {
	return ListContainersResponse{}
}

func (pm *podmanClient) ListImages(context.Context, time.Duration) ListImagesResponse {
	images, err := images.List(pm.ctx, nil)
	if err != nil {
		return ListImagesResponse{Error: err}
	}

	// Convert podman list image result to ListImagesResponse.
	resp := ListImagesResponse{}
	for _, img := range images {
		resp.ImageIDs = append(resp.ImageIDs, img.ID)
		resp.RepoTags = append(resp.RepoTags, img.RepoTags[0])
	}
	return resp
}

func (pm *podmanClient) CreateVolume(ctx context.Context, name string,
	driver string,
	driverOptions map[string]string,
	labels map[string]string,
	timeout time.Duration) SDKVolumeResponse {
	opts := entities.VolumeCreateOptions{
		Name: name,
		Driver: driver,
		Options: driverOptions,
		Label: labels,
	}
	resp, err := volumes.Create(pm.ctx, opts, nil)
	sdkResp := SDKVolumeResponse{}
	if err != nil {
		sdkResp.Error = err
		return sdkResp
	}
	sdkResp.DockerVolume = podmanVolumeConfigToDockerVolume(resp)
	return sdkResp
}

func podmanVolumeConfigToDockerVolume(pmVol *entities.VolumeConfigResponse) *types.Volume {
	vol := &types.Volume{}
	vol.Name = pmVol.Name
	vol.Driver = pmVol.Driver
	vol.CreatedAt = pmVol.CreatedAt.String()
	vol.Labels = pmVol.Labels
	vol.Mountpoint = pmVol.Mountpoint
	vol.Options = pmVol.Options
	vol.Scope = pmVol.Scope
	return vol
}

func (pm *podmanClient) InspectVolume(ctx context.Context, name string, timeout time.Duration) SDKVolumeResponse {
	resp, err := volumes.Inspect(pm.ctx, name, nil)
	sdkResp := SDKVolumeResponse{}
	if err != nil {
		sdkResp.Error = err
		return sdkResp
	}
	sdkResp.DockerVolume = podmanVolumeConfigToDockerVolume(resp)
	return sdkResp
}

func (pm *podmanClient) RemoveVolume(ctx context.Context, name string, timeout time.Duration) error {
	return volumes.Remove(pm.ctx, name, nil)
}

func (pm *podmanClient) ListPluginsWithFilters(context.Context, bool, []string, time.Duration) ([]string, error) {
	// Podman currently does not support plugins. Return empty result here.
	return []string{}, nil
}

func (pm *podmanClient) ListPlugins(context.Context, time.Duration, filters.Args) ListPluginsResponse {
	// Podman currently does not support plugins. Return empty result here.
	return ListPluginsResponse{}
}

func (pm *podmanClient) Stats(ctx context.Context, id string, d time.Duration) (<-chan *types.StatsJSON, <-chan error) {
	_, err := containers.Stats(pm.ctx, []string{id}, nil)
	statsChan := make(chan *types.StatsJSON)
	errChan := make(chan error)
	go func() {
		errChan <- err
	}()
	// Stats is currently not supported for podman container due to error:
	// "Error: stats is not supported in rootless mode without cgroups v2".
	// Hence not processing the result and just return the error here.
	return statsChan, errChan
}

func (pm *podmanClient) Version(context.Context, time.Duration) (string, error) {
	// Return an arbitrary Docker Version. This is only used by ACS/TACS handler to report the docker version
	// on the container instance.
	return "19.03.13-ce", nil
}

func (pm *podmanClient) APIVersion() (dockerclient.DockerVersion, error) {
	// Return an arbitrary API version. As far as I can tell, the caller of this method is not using the version
	// for anything anyway.
	return dockerclient.Version_1_21, nil
}

func (pm *podmanClient) InspectImage(id string) (*types.ImageInspect, error) {
	img, err := images.GetImage(pm.ctx, id, nil)
	if err != nil {
		return nil, err
	}
	// Convert podman image inspect result to docker image inspect result.
	resp := &types.ImageInspect{}
	resp.ID = img.ID
	resp.RepoTags = img.RepoTags
	resp.RepoDigests = img.RepoDigests
	resp.Parent = img.Parent
	resp.Comment = img.Comment

	return resp, nil
}

func (pm *podmanClient) RemoveImage(ctx context.Context, imageID string, d time.Duration) error {
	_, errs := images.Remove(pm.ctx, []string{imageID}, nil)
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (pm *podmanClient) LoadImage(ctx context.Context, r io.Reader, d time.Duration) error {
	_, err := images.Load(pm.ctx, r, nil)
	return err
}

func (pm *podmanClient) Info(context.Context, time.Duration) (types.Info, error) {
	pmInfo, err := system.Info(pm.ctx, nil)
	if err != nil {
		return types.Info{}, err
	}
	seelog.Infof("Got podman info, arch: %s, buildahVersion: %s", pmInfo.Host.Arch, pmInfo.Host.BuildahVersion)
	// The only thing we want from this API is security option. This is only recently added in podman
	// https://github.com/containers/podman/commit/04b43ccf64dd5166539743b44a95c9921ddc8a9f and not available in any released
	// version, so returning empty info here.
	return types.Info{}, nil
}
