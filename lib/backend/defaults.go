// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"time"
)

const (
	// DefaultBufferCapacity is a default circular buffer size
	// used by backends to fan out events
	DefaultBufferCapacity = 1024
	// DefaultBacklogGracePeriod is the default amount of time
	// that the circular buffer will tolerate an event backlog
	// in one of its watchers.
	DefaultBacklogGracePeriod = time.Second * 30
	// DefaultPollStreamPeriod is a default event poll stream period
	DefaultPollStreamPeriod = time.Second
	// DefaultEventsTTL is a default events TTL period
	DefaultEventsTTL = 10 * time.Minute
	// DefaultRangeLimit is used to specify some very large limit when limit is not specified
	// explicitly to prevent OOM due to infinite loops or other issues along those lines.
	DefaultRangeLimit = 200_000
)
