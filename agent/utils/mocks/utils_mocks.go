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
// Source: github.com/aws/amazon-ecs-agent/agent/utils (interfaces: LicenseProvider,Backoff)

// Package mock_utils is a generated GoMock package.
package mock_utils

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
)

// MockLicenseProvider is a mock of LicenseProvider interface
type MockLicenseProvider struct {
	ctrl     *gomock.Controller
	recorder *MockLicenseProviderMockRecorder
}

// MockLicenseProviderMockRecorder is the mock recorder for MockLicenseProvider
type MockLicenseProviderMockRecorder struct {
	mock *MockLicenseProvider
}

// NewMockLicenseProvider creates a new mock instance
func NewMockLicenseProvider(ctrl *gomock.Controller) *MockLicenseProvider {
	mock := &MockLicenseProvider{ctrl: ctrl}
	mock.recorder = &MockLicenseProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLicenseProvider) EXPECT() *MockLicenseProviderMockRecorder {
	return m.recorder
}

// GetText mocks base method
func (m *MockLicenseProvider) GetText() (string, error) {
	ret := m.ctrl.Call(m, "GetText")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetText indicates an expected call of GetText
func (mr *MockLicenseProviderMockRecorder) GetText() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetText", reflect.TypeOf((*MockLicenseProvider)(nil).GetText))
}

// MockBackoff is a mock of Backoff interface
type MockBackoff struct {
	ctrl     *gomock.Controller
	recorder *MockBackoffMockRecorder
}

// MockBackoffMockRecorder is the mock recorder for MockBackoff
type MockBackoffMockRecorder struct {
	mock *MockBackoff
}

// NewMockBackoff creates a new mock instance
func NewMockBackoff(ctrl *gomock.Controller) *MockBackoff {
	mock := &MockBackoff{ctrl: ctrl}
	mock.recorder = &MockBackoffMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockBackoff) EXPECT() *MockBackoffMockRecorder {
	return m.recorder
}

// Duration mocks base method
func (m *MockBackoff) Duration() time.Duration {
	ret := m.ctrl.Call(m, "Duration")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// Duration indicates an expected call of Duration
func (mr *MockBackoffMockRecorder) Duration() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Duration", reflect.TypeOf((*MockBackoff)(nil).Duration))
}

// Reset mocks base method
func (m *MockBackoff) Reset() {
	m.ctrl.Call(m, "Reset")
}

// Reset indicates an expected call of Reset
func (mr *MockBackoffMockRecorder) Reset() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reset", reflect.TypeOf((*MockBackoff)(nil).Reset))
}
