// +build !linux

package task

import (
	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apierrors "github.com/aws/amazon-ecs-agent/agent/api/errors"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/taskresource"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/pkg/errors"
)

// getFirelensContainer is an unimplemented method on non linux platform.
func (task *Task) getFirelensContainer() *apicontainer.Container {
	return nil
}

// firelensDependsOnSecret is an unimplemented method on non linux platform.
func (task *Task) firelensDependsOnSecretResource(secretProvider string) bool {
	return false
}

// applyFirelensSetup is an unimplemented method on non linux platform.
func (task *Task) applyFirelensSetup(cfg *config.Config, resourceFields *taskresource.ResourceFields,
	firelensContainer *apicontainer.Container) error {
	return errors.New("unsupported platform")
}

// AddFirelensContainerBindMounts is an unimplemented method on non linux platform.
func (task *Task) AddFirelensContainerBindMounts(firelensConfigType string, hostConfig *dockercontainer.HostConfig,
	config *config.Config) *apierrors.HostConfigError {
	return &apierrors.HostConfigError{Msg: "unsupported platform"}
}

// PopulateSecretLogOptionsToFirelensContainer is an unimplemented method on non linux platform.
func (task *Task) PopulateSecretLogOptionsToFirelensContainer(firelensContainer *apicontainer.Container) *apierrors.DockerClientConfigError {
	return &apierrors.DockerClientConfigError{Msg: "unsupported platform"}
}