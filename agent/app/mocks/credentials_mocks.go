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
// Source: github.com/aws/aws-sdk-go/aws/credentials (interfaces: Provider)

// Package mock_credentials is a generated GoMock package.
package mock_credentials

import (
	reflect "reflect"

	credentials "github.com/aws/aws-sdk-go/aws/credentials"
	gomock "github.com/golang/mock/gomock"
)

// MockProvider is a mock of Provider interface
type MockProvider struct {
	ctrl     *gomock.Controller
	recorder *MockProviderMockRecorder
}

// MockProviderMockRecorder is the mock recorder for MockProvider
type MockProviderMockRecorder struct {
	mock *MockProvider
}

// NewMockProvider creates a new mock instance
func NewMockProvider(ctrl *gomock.Controller) *MockProvider {
	mock := &MockProvider{ctrl: ctrl}
	mock.recorder = &MockProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockProvider) EXPECT() *MockProviderMockRecorder {
	return m.recorder
}

// IsExpired mocks base method
func (m *MockProvider) IsExpired() bool {
	ret := m.ctrl.Call(m, "IsExpired")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsExpired indicates an expected call of IsExpired
func (mr *MockProviderMockRecorder) IsExpired() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsExpired", reflect.TypeOf((*MockProvider)(nil).IsExpired))
}

// Retrieve mocks base method
func (m *MockProvider) Retrieve() (credentials.Value, error) {
	ret := m.ctrl.Call(m, "Retrieve")
	ret0, _ := ret[0].(credentials.Value)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Retrieve indicates an expected call of Retrieve
func (mr *MockProviderMockRecorder) Retrieve() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Retrieve", reflect.TypeOf((*MockProvider)(nil).Retrieve))
}
