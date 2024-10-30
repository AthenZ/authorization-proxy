// Copyright 2024 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infra

import (
	"net/http/httputil"
	"sync"
	"sync/atomic"
)

type simpleBuffer struct {
	pool sync.Pool
	size *uint64
}

// NewSimpleBuffer implements httputil.BufferPool for providing byte slices of same size.
func NewSimpleBuffer(size uint64) httputil.BufferPool {
	if size == 0 {
		return nil
	}

	b := &simpleBuffer{
		size: &size,
	}

	b.pool = sync.Pool{
		New: func() interface{} {
			return make([]byte, atomic.LoadUint64(b.size))
		},
	}

	return b
}

// Get returns a slice from the pool, and remove it from the pool. New slice may be created when needed.
func (b *simpleBuffer) Get() []byte {
	return b.pool.Get().([]byte)
}

// Put adds the given slice back to internal pool.
func (b *simpleBuffer) Put(buf []byte) {
	bufCap := cap(buf)
	b.pool.Put(buf[0:bufCap])
}
