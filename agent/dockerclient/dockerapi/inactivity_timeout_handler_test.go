// +build unit

// Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package dockerapi

import (
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testTimeout = 100 * time.Millisecond
)

func TestHandleInactivityTimeout(t *testing.T) {
	var wg sync.WaitGroup

	checkReadActivityOnceFunc = func(pr *proxyReader, timeout time.Duration, cancelRequest func(), canceled *uint32, done chan struct{}, lastCallCount uint64) (uint64, bool) {
		assert.Equal(t, timeout, testTimeout)
		wg.Done()
		return lastCallCount, true
	}
	defer func() {
		checkReadActivityOnceFunc = checkReadActivityOnce
	}()

	var canceled uint32
	reader := ioutil.NopCloser(strings.NewReader("test"))
	go func() {
		wg.Add(1)
		handleInactivityTimeout(reader, testTimeout, func() {}, &canceled)
	}()

	wg.Wait()
}

func TestCheckReadActivityOnce(t *testing.T) {
	testCases := []struct {
		name            string
		readerCallCount uint64
		expectCallCount uint64
		expectFinish    bool
	}{
		{
			name:            "Test check read activity with new read activity",
			readerCallCount: 1,
			expectCallCount: 1,
			expectFinish:    false,
		},
		{
			name:            "Test check read activity without new read activity",
			readerCallCount: 0,
			expectCallCount: 0,
			expectFinish:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pReader := &proxyReader{ReadCloser: ioutil.NopCloser(strings.NewReader("test"))}
			pReader.calls = tc.readerCallCount
			var canceled uint32
			done := make(chan struct{})
			callCount, finished := checkReadActivityOnce(pReader, testTimeout, func() {}, &canceled, done, 0)
			assert.Equal(t, tc.expectCallCount, callCount)
			assert.Equal(t, tc.expectFinish, finished)
		})
	}
}
