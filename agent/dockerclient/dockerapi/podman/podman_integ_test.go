//+build integration,podman

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
	"os"
	"testing"
	"time"

	"github.com/containers/podman/v2/pkg/bindings"
	"github.com/docker/docker/api/types/filters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
These tests required manually setting up a podman socket and specify it in "TEST_PODMAN_SOCKET" env. Example:
TEST_PODMAN_SOCKET="unix:/run/user/1000/podman/podman.sock" go test -v -tags integration,podman -count 1 ./agent/dockerclient/dockerapi/podman
*/

const (
	testDuration = 5 * time.Second
)

func newTestClient(t *testing.T, ctx context.Context) *podmanClient {
	socket := os.Getenv("TEST_PODMAN_SOCKET")
	t.Logf("Using socket: %s", socket)
	connText, err := bindings.NewConnection(ctx, socket)
	require.NoError(t, err)
	return &podmanClient{
		ctx: connText,
	}
}

func TestListAndInspectImages(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t, ctx)
	resp := client.ListImages(ctx, testDuration)
	assert.NoError(t, resp.Error)
	t.Logf("List image response: %+v", resp)

	// This test currently assumes there are some images on the host for inspections.
	for _, imageID := range resp.ImageIDs {
		resp, err := client.InspectImage(imageID)
		require.NoError(t, err)
		t.Logf("Successfully inspected image [%s], result: %+v", imageID, *resp)
	}
}

func TestLoadAndRemoveImage(t *testing.T) {
	testImageTar := "/tmp/busybox.tar"
	_, err := os.Stat(testImageTar)
	if err != nil {
		t.Skipf("Test assumes there's an image tar at %s. Did not find it here.", testImageTar)
	}
	r, err := os.Open(testImageTar)
	require.NoError(t, err)
	defer r.Close()

	ctx := context.Background()
	client := newTestClient(t, ctx)
	err = client.LoadImage(ctx, r, testDuration)
	require.NoError(t, err)
	t.Logf("Successfully loaded busybox image from %s", testImageTar)

	err = client.RemoveImage(ctx, "busybox", testDuration)
	require.NoError(t, err)
	t.Logf("Successfully removed busybox image")
}

func TestVolume(t *testing.T) {
	testVolName := "test-vol"
	testVolDriver := "local"
	testVolOpts := map[string]string{
		"type": "tmpfs",
	}
	testVolLabels := map[string]string{
		"foo": "bar",
	}
	ctx := context.Background()
	client := newTestClient(t, ctx)
	resp := client.CreateVolume(ctx, testVolName, testVolDriver, testVolOpts, testVolLabels, testDuration)
	require.NoError(t, resp.Error)
	t.Logf("Successfully created test volume [%s].", testVolName)
	resp = client.InspectVolume(ctx, testVolName, testDuration)
	require.NoError(t, resp.Error)
	t.Logf("Successfully inspected test volume [%s]. Response: %+v", testVolName, *resp.DockerVolume)
	err := client.RemoveVolume(ctx, testVolName, testDuration)
	require.NoError(t, err)
	t.Logf("Successfully removed test volume [%s].", testVolName)
}

func TestListPlugins(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t, ctx)
	resp := client.ListPlugins(ctx, testDuration, filters.Args{})
	assert.NoError(t, resp.Error)

	_, err := client.ListPluginsWithFilters(ctx, false, []string{}, testDuration)
	assert.NoError(t, err)
}

func TestVersion(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t, ctx)
	version, err := client.Version(ctx, testDuration)
	require.NoError(t, err)
	assert.NotEmpty(t, version)

	_, err = client.APIVersion()
	assert.NoError(t, err)
}

func TestInfo(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t, ctx)
	_, err := client.Info(ctx, testDuration)
	assert.NoError(t, err)
}