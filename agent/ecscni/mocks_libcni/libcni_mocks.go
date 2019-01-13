// Copyright 2015-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/containernetworking/cni/libcni (interfaces: CNI)

// Package mock_libcni is a generated GoMock package.
package mock_libcni

import (
	reflect "reflect"

	libcni "github.com/containernetworking/cni/libcni"
	types "github.com/containernetworking/cni/pkg/types"
	gomock "github.com/golang/mock/gomock"
)

// MockCNI is a mock of CNI interface
type MockCNI struct {
	ctrl     *gomock.Controller
	recorder *MockCNIMockRecorder
}

// MockCNIMockRecorder is the mock recorder for MockCNI
type MockCNIMockRecorder struct {
	mock *MockCNI
}

// NewMockCNI creates a new mock instance
func NewMockCNI(ctrl *gomock.Controller) *MockCNI {
	mock := &MockCNI{ctrl: ctrl}
	mock.recorder = &MockCNIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockCNI) EXPECT() *MockCNIMockRecorder {
	return m.recorder
}

// AddNetwork mocks base method
func (m *MockCNI) AddNetwork(arg0 *libcni.NetworkConfig, arg1 *libcni.RuntimeConf) (types.Result, error) {
	ret := m.ctrl.Call(m, "AddNetwork", arg0, arg1)
	ret0, _ := ret[0].(types.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddNetwork indicates an expected call of AddNetwork
func (mr *MockCNIMockRecorder) AddNetwork(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNetwork", reflect.TypeOf((*MockCNI)(nil).AddNetwork), arg0, arg1)
}

// AddNetworkList mocks base method
func (m *MockCNI) AddNetworkList(arg0 *libcni.NetworkConfigList, arg1 *libcni.RuntimeConf) (types.Result, error) {
	ret := m.ctrl.Call(m, "AddNetworkList", arg0, arg1)
	ret0, _ := ret[0].(types.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddNetworkList indicates an expected call of AddNetworkList
func (mr *MockCNIMockRecorder) AddNetworkList(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNetworkList", reflect.TypeOf((*MockCNI)(nil).AddNetworkList), arg0, arg1)
}

// DelNetwork mocks base method
func (m *MockCNI) DelNetwork(arg0 *libcni.NetworkConfig, arg1 *libcni.RuntimeConf) error {
	ret := m.ctrl.Call(m, "DelNetwork", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DelNetwork indicates an expected call of DelNetwork
func (mr *MockCNIMockRecorder) DelNetwork(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelNetwork", reflect.TypeOf((*MockCNI)(nil).DelNetwork), arg0, arg1)
}

// DelNetworkList mocks base method
func (m *MockCNI) DelNetworkList(arg0 *libcni.NetworkConfigList, arg1 *libcni.RuntimeConf) error {
	ret := m.ctrl.Call(m, "DelNetworkList", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DelNetworkList indicates an expected call of DelNetworkList
func (mr *MockCNIMockRecorder) DelNetworkList(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelNetworkList", reflect.TypeOf((*MockCNI)(nil).DelNetworkList), arg0, arg1)
}
