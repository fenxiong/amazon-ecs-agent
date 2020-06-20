// Code generated by MockGen. DO NOT EDIT.
// Source: agent/stats/task.go

// Package mock_stats is a generated GoMock package.
package mock_stats

import (
	types "github.com/docker/docker/api/types"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockTaskStatsInterface is a mock of TaskStatsInterface interface.
type MockTaskStatsInterface struct {
	ctrl     *gomock.Controller
	recorder *MockTaskStatsInterfaceMockRecorder
}

// MockTaskStatsInterfaceMockRecorder is the mock recorder for MockTaskStatsInterface.
type MockTaskStatsInterfaceMockRecorder struct {
	mock *MockTaskStatsInterface
}

// NewMockTaskStatsInterface creates a new mock instance.
func NewMockTaskStatsInterface(ctrl *gomock.Controller) *MockTaskStatsInterface {
	mock := &MockTaskStatsInterface{ctrl: ctrl}
	mock.recorder = &MockTaskStatsInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTaskStatsInterface) EXPECT() *MockTaskStatsInterfaceMockRecorder {
	return m.recorder
}

// GetAWSVPCNetworkStats mocks base method.
func (m *MockTaskStatsInterface) GetAWSVPCNetworkStats(arg0 []string, arg1 string, arg2 int) (<-chan *types.StatsJSON, <-chan error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAWSVPCNetworkStats", arg0, arg1, arg2)
	ret0, _ := ret[0].(<-chan *types.StatsJSON)
	ret1, _ := ret[1].(<-chan error)
	return ret0, ret1
}

// GetAWSVPCNetworkStats indicates an expected call of GetAWSVPCNetworkStats.
func (mr *MockTaskStatsInterfaceMockRecorder) GetAWSVPCNetworkStats(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAWSVPCNetworkStats", reflect.TypeOf((*MockTaskStatsInterface)(nil).GetAWSVPCNetworkStats), arg0, arg1, arg2)
}

// PopulateNIDeviceList mocks base method.
func (m *MockTaskStatsInterface) PopulateNIDeviceList(containerPID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PopulateNIDeviceList", containerPID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PopulateNIDeviceList indicates an expected call of PopulateNIDeviceList.
func (mr *MockTaskStatsInterfaceMockRecorder) PopulateNIDeviceList(containerPID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PopulateNIDeviceList", reflect.TypeOf((*MockTaskStatsInterface)(nil).PopulateNIDeviceList), containerPID)
}