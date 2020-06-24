//+build unit

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

package stats

import (
	"context"
	"errors"
	mock_stats "github.com/aws/amazon-ecs-agent/agent/stats/mock"
	mock_utils "github.com/aws/amazon-ecs-agent/agent/utils/mocks"

	"testing"
	"time"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apitask "github.com/aws/amazon-ecs-agent/agent/api/task"
	apitaskstatus "github.com/aws/amazon-ecs-agent/agent/api/task/status"
	mock_netlink "github.com/aws/amazon-ecs-agent/agent/eni/netlinkwrapper/mocks"
	mock_resolver "github.com/aws/amazon-ecs-agent/agent/stats/resolver/mock"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docker/docker/api/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

var statsDataTask = []*StatTestData{
	{parseNanoTime("2015-02-12T21:22:05.131117533Z"), 22400432, 1839104},
	{parseNanoTime("2015-02-12T21:22:05.232291187Z"), 116499979, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.333776335Z"), 248503503, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.434753595Z"), 372167097, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.535746779Z"), 502862518, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.638709495Z"), 638485801, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.739985398Z"), 780707806, 3649536},
	{parseNanoTime("2015-02-12T21:22:05.840941705Z"), 911624529, 3649536},
}

var statsNetworkData1 = map[string]types.NetworkStats{
	"eth0": types.NetworkStats{
		RxBytes:   uint64(100),
		RxPackets: uint64(10),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
	"eth1": types.NetworkStats{
		RxBytes:   uint64(50),
		RxPackets: uint64(5),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
}

var statsNetworkData2 = map[string]types.NetworkStats{
	"eth0": types.NetworkStats{
		RxBytes:   uint64(99),
		RxPackets: uint64(9),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
	"eth1": types.NetworkStats{
		RxBytes:   uint64(49),
		RxPackets: uint64(4),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
}

var statsNetworkData3 = map[string]types.NetworkStats{
	"eth0": types.NetworkStats{
		RxBytes:   uint64(98),
		RxPackets: uint64(8),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
	"eth1": types.NetworkStats{
		RxBytes:   uint64(48),
		RxPackets: uint64(5),
		RxErrors:  uint64(0),
		RxDropped: uint64(0),
		TxBytes:   uint64(0),
		TxPackets: uint64(0),
		TxErrors:  uint64(0),
		TxDropped: uint64(0),
	},
}

var statsNetworkData = []map[string]types.NetworkStats{
	statsNetworkData1, statsNetworkData2, statsNetworkData3,
}

func TestStats(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNS := mock_utils.NewMockNS(ctrl)
	mockNetLink := mock_netlink.NewMockNetLink(ctrl)

	mockNS.EXPECT().WithNetNSPath("/host/proc/123/ns/net", gomock.Any()).Do(func(nsPath interface{}, toRun func(n ns.NetNS) error) error {
		return toRun(nil)
	})
	mockNetLink.EXPECT().LinkByName("eth0").Return(&netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Name: "name",
			Statistics: &netlink.LinkStatistics{
				RxPackets: uint64(1),
			},
		},
	}, nil)

	taskstatsclient := &TaskStatsStruct{
		nsclient: mockNS,
		netlinkClient: mockNetLink,
	}
	statsChan, _ := taskstatsclient.GetAWSVPCNetworkStats([]string{"eth0"}, "123", 1)
	stats := <- statsChan
	require.NotNil(t, stats)
	require.Contains(t, stats.Networks, "name")
	assert.Equal(t, uint64(1), stats.Networks["name"].RxPackets)
}

func TestTaskStatsCollection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	resolver := mock_resolver.NewMockContainerMetadataResolver(ctrl)
	mockTaskstats := mock_stats.NewMockTaskStatsInterface(ctrl)

	nsmock := mock_utils.NewMockNS(ctrl)
	containerPID := "23"
	taskId := "task1"
	ctx, cancel := context.WithCancel(context.TODO())
	taskStats := &StatsTask{
		TaskMetadata: &TaskMetadata{
			TaskArn:      taskId,
			ContainerPID: containerPID,
			DeviceName:   []string{"device1", "device2"},
		},
		Ctx:      ctx,
		Cancel:   cancel,
		Resolver: resolver,
		client:   mockTaskstats,
		//netlinkinterface:   mockNetlink,
		nswrapperinterface: nsmock,
	}
	testTask := &apitask.Task{
		Containers: []*apicontainer.Container{
			{Name: "c1",},
			{Name: "c2",},
		},
		KnownStatusUnsafe: apitaskstatus.TaskRunning,
	}
	resolver.EXPECT().ResolveTaskByARN(gomock.Any()).Return(testTask, nil).AnyTimes()
	statChan := make(chan *types.StatsJSON)
	errC := make(chan error)
	mockTaskstats.EXPECT().GetAWSVPCNetworkStats(gomock.Any(), gomock.Any(), gomock.Any()).Return(statChan, errC).AnyTimes()

	go func() {
		for index, networkDatum := range statsNetworkData {
			dockerStat := &types.StatsJSON{}
			dockerStat.Read = statsDataTask[index].timestamp
			dockerStat.Networks = networkDatum
			statChan <- dockerStat
		}
	}()

	taskStats.StartStatsCollectionTask()
	time.Sleep(checkPointSleep)
	taskStats.StopStatsCollectionTask()
	networkStatsSet, err := taskStats.StatsQueue.GetNetworkStatsSet()

	assert.NoError(t, err)
	assert.NotNil(t, networkStatsSet)
	assert.EqualValues(t, 444, *networkStatsSet.RxBytes.Sum)
	assert.EqualValues(t, 41, *networkStatsSet.RxPackets.Sum)
	assert.EqualValues(t, 3, *networkStatsSet.RxPackets.SampleCount)
	assert.EqualValues(t, 3, *networkStatsSet.TxPackets.SampleCount)
}

func TestTaskStatsCollectionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	resolver := mock_resolver.NewMockContainerMetadataResolver(ctrl)
	mockTaskstats := mock_stats.NewMockTaskStatsInterface(ctrl)


	taskId := "task1"
	testTask := &apitask.Task{Containers: []*apicontainer.Container{{Name: "c1",},},
		KnownStatusUnsafe: apitaskstatus.TaskRunning,}

	ctx, cancel := context.WithCancel(context.TODO())
	taskStats := &StatsTask{
		TaskMetadata: &TaskMetadata{
			TaskArn:    taskId,
			DeviceName: []string{"device1"},
		},
		Ctx:      ctx,
		Cancel:   cancel,
		Resolver: resolver,
		client:   mockTaskstats,
	}
	statChan := make(chan *types.StatsJSON)
	errC := make(chan error)
	resolver.EXPECT().ResolveTaskByARN(gomock.Any()).Return(testTask, nil).AnyTimes()
	mockTaskstats.EXPECT().GetAWSVPCNetworkStats(gomock.Any(), gomock.Any(), gomock.Any()).Return(statChan, errC).AnyTimes()

	go func() {
		for index, networkDatum := range statsNetworkData {
			dockerStat := &types.StatsJSON{}
			dockerStat.Read = statsDataTask[index].timestamp
			dockerStat.Networks = networkDatum
			statChan <- dockerStat
		}
		err := errors.New("emit macho dwarf: elf header corrupted")
		errC <- err
	}()

	taskStats.StartStatsCollectionTask()
	time.Sleep(checkPointSleep)
	taskStats.StopStatsCollectionTask()

	networkStatsSet, err := taskStats.StatsQueue.GetNetworkStatsSet()
	assert.NoError(t, err)
	assert.EqualValues(t, 444, *networkStatsSet.RxBytes.Sum)
	assert.EqualValues(t, 41, *networkStatsSet.RxPackets.Sum)
	assert.EqualValues(t, 3, *networkStatsSet.RxPackets.SampleCount)
	assert.EqualValues(t, 3, *networkStatsSet.TxPackets.SampleCount)
}

func TestGetDeviceList(t *testing.T) {

	link1 := &netlink.GenericLink{
		LinkType: linkTypeDevice,
		LinkAttrs: netlink.LinkAttrs{
			Name: "link1device",
		},
	}
	link2 := &netlink.GenericLink{
		LinkType: linkTypeVlan,
		LinkAttrs: netlink.LinkAttrs{
			Name: "link2device",
		},
	}
	link3 := &netlink.GenericLink{
		LinkType: "randomLinkType",
		LinkAttrs: netlink.LinkAttrs{
			Name: "link3device",
		},
	}
	link4 := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			EncapType: encapTypeLoopback,
			Name:      "link4device",
		},
		LinkType: linkTypeVlan,
	}
	linkList := []netlink.Link{link1, link2, link3, link4}

	deviceNames := getDevicesList(linkList)

	assert.ElementsMatch(t, []string{"link1device", "link2device"}, deviceNames)
}
