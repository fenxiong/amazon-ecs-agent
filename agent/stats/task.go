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
	"fmt"
	apitaskstatus "github.com/aws/amazon-ecs-agent/agent/api/task/status"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/ecscni"
	"github.com/aws/amazon-ecs-agent/agent/stats/resolver"
	"github.com/aws/amazon-ecs-agent/agent/utils/nswrapper"
	"github.com/aws/amazon-ecs-agent/agent/eni/netlinkwrapper"
	"github.com/containernetworking/plugins/pkg/ns"

	dockerstats "github.com/docker/docker/api/types"
	"github.com/cihub/seelog"
	"github.com/docker/docker/api/types"
	netlinklib "github.com/vishvananda/netlink"
	//"math/rand"
	//"time"
)

const (
	// linkTypeDevice defines the string that's expected to be the output of
	// netlink.Link.Type() method for netlink.Device type.
	linkTypeDevice = "device"
	linkTypeVlan   = "vlan"
	// encapTypeLoopback defines the string that's set for the link.Attrs.EncapType
	// field for localhost devices. The EncapType field defines the link
	// encapsulation method. For localhost, it's set to "loopback".
	encapTypeLoopback = "loopback"
)
type TaskStatsInterface interface {
	GetAWSVPCNetworkStats([]string, string, int)(<-chan *types.StatsJSON, <-chan error)
	PopulateNIDeviceList(containerPID string) ([]string, error)
}

type TaskStatsStruct struct {
	netlinkClient netlinkwrapper.NetLink
	nsclient nswrapper.NS
}


func newStatsTaskContainer(taskARN string, containerPID string, numberOfContainers int,
	resolver resolver.ContainerMetadataResolver) (*StatsTask, error) {
	nsAgent := nswrapper.NewNS()
	netlinkclient := netlinkwrapper.New()

	taskStatsStruct := &TaskStatsStruct{
		netlinkClient: netlinkclient,
		nsclient:      nsAgent,
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &StatsTask{
		TaskMetadata: &TaskMetadata{
			TaskArn:          taskARN,
			ContainerPID:     containerPID,
			NumberContainers: numberOfContainers,
		},
		Ctx:      ctx,
		Cancel:   cancel,
		Resolver: resolver,
		client:   taskStatsStruct,
	}, nil

}

func (task *StatsTask) StartStatsCollectionTask() {
	queueSize := int(config.DefaultContainerMetricsPublishInterval.Seconds() * 4)
	task.StatsQueue = NewQueue(queueSize)
	task.StatsQueue.Reset()
	go task.collect()
}

func (task *StatsTask) StopStatsCollectionTask() {
	task.Cancel()
}

func (taskStat *StatsTask) collect() {
	taskArn := taskStat.TaskMetadata.TaskArn
	for {
		select {
		case <-taskStat.Ctx.Done():
			seelog.Debugf("Stopping stats collection for taskStat %s", taskArn)
			return
		default:
			err := taskStat.processStatsStream()
			if err != nil {
				seelog.Debugf("Error querying stats for task %s: %v", taskArn, err)
			}
			// We were disconnected from the stats stream.
			// Check if the task is terminal. If it is, stop collecting metrics.
			terminal, err := taskStat.terminal()
			if err != nil {
				// Error determining if the task is terminal. clean-up anyway.
				seelog.Warnf("Error determining if the task %s is terminal, stopping stats collection: %v",
					taskArn, err)
				taskStat.StopStatsCollectionTask()
			} else if terminal {
				seelog.Infof("Task %s is terminal, stopping stats collection", taskArn)
				taskStat.StopStatsCollectionTask()
			}
		}
	}
}

func (taskStat *StatsTask) processStatsStream() error {
	taskArn := taskStat.TaskMetadata.TaskArn
	if len(taskStat.TaskMetadata.DeviceName) == 0 {
		var err error
		taskStat.TaskMetadata.DeviceName, err = taskStat.client.PopulateNIDeviceList(taskStat.TaskMetadata.ContainerPID)
		if err != nil {
			return err
		}
	}
	awsvpcNetworkStats, errC := taskStat.client.GetAWSVPCNetworkStats(taskStat.TaskMetadata.DeviceName,
		taskStat.TaskMetadata.ContainerPID, taskStat.TaskMetadata.NumberContainers)

	returnError := false
	for {
		select {
		case <-taskStat.Ctx.Done():
			return nil
		case err := <-errC:
			seelog.Warnf("Error encountered processing metrics stream from host, this may affect "+
				"cloudwatch metric accuracy: %s", err)
			returnError = true
		case rawStat, ok := <-awsvpcNetworkStats:
			seelog.Info("got stats")
			if !ok {
				if returnError {
					return fmt.Errorf("error encountered processing metrics stream from host")
				}
				return nil
			}
			if err := taskStat.StatsQueue.Add(rawStat); err != nil {
				seelog.Warnf("Task [%s]: error converting stats: %v", taskArn, err)
			}
		}
	}

}

func (task *StatsTask) terminal() (bool, error) {
	resolvedTask, err := task.Resolver.ResolveTaskByARN(task.TaskMetadata.TaskArn)
	if err != nil {
		return false, err
	}
	return resolvedTask.GetKnownStatus() == apitaskstatus.TaskStopped, nil
}

func getDevicesList(linkList []netlinklib.Link) []string {
	var deviceNames []string
	for _, link := range linkList {
		if link.Type() != linkTypeDevice && link.Type() != linkTypeVlan {
			// We only care about netlink.Device/netlink.Vlan types. Ignore other link types.
			continue
		}
		if link.Attrs().EncapType == encapTypeLoopback {
			// Ignore localhost
			continue
		}
		deviceNames = append(deviceNames, link.Attrs().Name)
	}
	return deviceNames
}

func (taskstatsclient *TaskStatsStruct) PopulateNIDeviceList(containerPID string) ([]string, error) {
	var err error
	var deviceList []string
	netNSPath := fmt.Sprintf(ecscni.NetnsFormat, containerPID)
	err = taskstatsclient.nsclient.WithNetNSPath(netNSPath, func(ns.NetNS) error {
		linksInTaskNetNS, linkErr := taskstatsclient.netlinkClient.LinkList()
		deviceNames := getDevicesList(linksInTaskNetNS)
		deviceList = append(deviceList, deviceNames...)
		return linkErr
	})
	return deviceList, err
}

func linkStatsToDockerStats(netLinkStats *netlinklib.LinkStatistics, numberOfContainers uint64) dockerstats.NetworkStats {
	networkStats := dockerstats.NetworkStats{
		RxBytes:   netLinkStats.RxBytes / numberOfContainers,
		RxPackets: netLinkStats.RxPackets / numberOfContainers,
		RxErrors:  netLinkStats.RxErrors / numberOfContainers,
		RxDropped: netLinkStats.RxDropped / numberOfContainers,
		TxBytes:   netLinkStats.TxBytes / numberOfContainers,
		TxPackets: netLinkStats.TxPackets / numberOfContainers,
		TxErrors:  netLinkStats.TxErrors / numberOfContainers,
		TxDropped: netLinkStats.TxDropped / numberOfContainers,
	}
	return networkStats
}

func (taskstatsclient *TaskStatsStruct) GetAWSVPCNetworkStats(deviceList []string, containerPID string,
	numberOfContainers int) (<-chan *types.StatsJSON, <-chan error) {

	errC := make(chan error)
	statsC := make(chan *dockerstats.StatsJSON)

	go func() {
		// time.Sleep(time.Second * time.Duration(rand.Intn(int(config.DefaultPollingMetricsWaitDuration))))
		networkStats := make(map[string]dockerstats.NetworkStats)
		for _, device := range deviceList {
			var link netlinklib.Link
			err := taskstatsclient.nsclient.WithNetNSPath(fmt.Sprintf(ecscni.NetnsFormat, containerPID),
				func(ns.NetNS) error {
					var linkErr error
					if link, linkErr = taskstatsclient.netlinkClient.LinkByName(device); linkErr != nil {
						return linkErr
					}
					return nil
				})
			if err != nil {
				errC <- err
				return
			}

			netLinkStats := link.Attrs().Statistics
			networkStats[link.Attrs().Name] = linkStatsToDockerStats(netLinkStats, uint64(numberOfContainers))
		}
		dockerStats := &types.StatsJSON{
			Networks: networkStats,
		}
		statsC <- dockerStats
	}()
	return statsC, errC
}
