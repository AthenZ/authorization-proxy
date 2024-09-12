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
	"reflect"
	"sync"
	"testing"
)

func TestNewSimpleBuffer(t *testing.T) {
	type args struct {
		size uint64
	}
	type testcase struct {
		name      string
		args      args
		want      *simpleBuffer
		checkFunc func(got, want *simpleBuffer) error
	}
	tests := []testcase{
		{
			name: "Check newBuffer, with 0 size",
			args: args{
				size: 0,
			},
			want: nil,
			checkFunc: func(got, want *simpleBuffer) error {
				if !reflect.DeepEqual(got, want) {
					return &NotEqualError{"", got, want}
				}
				return nil
			},
		},
		{
			name: "Check newBuffer, positive size",
			args: args{
				size: 37,
			},
			want: &simpleBuffer{
				size: func(i uint64) *uint64 { return &i }(37),
			},
			checkFunc: func(got, want *simpleBuffer) error {
				if *(got.size) != *(want.size) {
					return &NotEqualError{"size", *(got.size), *(want.size)}
				}

				buffer := got.Get()
				if uint64(cap(buffer)) != *(want.size) {
					return &NotEqualError{"pool", cap(buffer), *(want.size)}
				}

				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSimpleBuffer(tt.args.size)

			if got == nil && tt.want == nil {
				// skip on both nil
				return
			}
			if err := tt.checkFunc(got.(*simpleBuffer), tt.want); err != nil {
				t.Errorf("newBuffer() %v", err)
				return
			}
		})
	}
}

func TestSimpleBufferGet(t *testing.T) {
	type fields struct {
		pool sync.Pool
		size *uint64
	}
	type testcase struct {
		name   string
		fields fields
		want   []byte
	}
	tests := []testcase{
		{
			name: "Check simpleBuffer Get, get from internal pool",
			fields: fields{
				pool: sync.Pool{
					New: func() interface{} {
						return []byte("pool-new-91")
					},
				},
			},
			want: []byte("pool-new-91"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &simpleBuffer{
				pool: tt.fields.pool,
				size: tt.fields.size,
			}

			got := b.Get()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("simpleBuffer.Get() %v", &NotEqualError{"", got, tt.want})
				return
			}
		})
	}
}

func TestSimpleBufferPut(t *testing.T) {
	type fields struct {
		pool sync.Pool
		size *uint64
	}
	type args struct {
		buf []byte
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		checkFunc func(got *simpleBuffer) error
	}
	tests := []testcase{
		{
			name: "Check simpleBuffer Put, with 0 size",
			fields: fields{
				pool: sync.Pool{New: func() interface{} { return make([]byte, 128) }},
				size: func(i uint64) *uint64 { return &i }(128),
			},
			args: args{
				buf: make([]byte, 0),
			},
			checkFunc: func(got *simpleBuffer) error {
				wantSize := uint64(128)
				wantBufLen := 0
				wantBufCap := 0

				gotSize := *(got.size)
				if gotSize != wantSize {
					return &NotEqualError{"size", gotSize, wantSize}
				}

				gotBuffer := got.Get()
				gotBufLen := len(gotBuffer)
				if gotBufLen != wantBufLen {
					return &NotEqualError{"buffer len", gotBufLen, wantBufLen}
				}
				gotBufCap := cap(gotBuffer)
				if gotBufCap != wantBufCap {
					return &NotEqualError{"buffer cap", gotBufCap, wantBufCap}
				}
				return nil
			},
		},
		{
			name: "Check simpleBuffer Put, with buffer len and cap > current size",
			fields: fields{
				pool: sync.Pool{New: func() interface{} { return make([]byte, 128) }},
				size: func(i uint64) *uint64 { return &i }(128),
			},
			args: args{
				buf: make([]byte, 129),
			},
			checkFunc: func(got *simpleBuffer) error {
				wantSize := uint64(128)
				wantBufLen := 129
				wantBufCap := 129

				gotSize := *(got.size)
				if gotSize != wantSize {
					return &NotEqualError{"size", gotSize, wantSize}
				}

				gotBuffer := got.Get()
				gotBufLen := len(gotBuffer)
				if gotBufLen != wantBufLen {
					return &NotEqualError{"len(buffer)", gotBufLen, wantBufLen}
				}
				gotBufCap := cap(gotBuffer)
				if gotBufCap != wantBufCap {
					return &NotEqualError{"cap(buffer)", gotBufCap, wantBufCap}
				}
				return nil
			},
		},
		{
			name: "Check simpleBuffer Put, with buffer len and cap == current size",
			fields: fields{
				pool: sync.Pool{New: func() interface{} { return make([]byte, 128) }},
				size: func(i uint64) *uint64 { return &i }(128),
			},
			args: args{
				buf: make([]byte, 128),
			},
			checkFunc: func(got *simpleBuffer) error {
				wantSize := uint64(128)
				wantBufLen := 128
				wantBufCap := 128

				gotSize := *(got.size)
				if gotSize != wantSize {
					return &NotEqualError{"size", gotSize, wantSize}
				}

				gotBuffer := got.Get()
				gotBufLen := len(gotBuffer)
				if gotBufLen != wantBufLen {
					return &NotEqualError{"len(buffer)", gotBufLen, wantBufLen}
				}
				gotBufCap := cap(gotBuffer)
				if gotBufCap != wantBufCap {
					return &NotEqualError{"cap(buffer)", gotBufCap, wantBufCap}
				}
				return nil
			},
		},
		{
			name: "Check simpleBuffer Put, with buffer len > cap",
			fields: fields{
				pool: sync.Pool{New: func() interface{} { return make([]byte, 128) }},
				size: func(i uint64) *uint64 { return &i }(128),
			},
			args: args{
				buf: make([]byte, 129, 256),
			},
			checkFunc: func(got *simpleBuffer) error {
				wantSize := uint64(128)
				wantBufLen := 256
				wantBufCap := 256

				gotSize := *(got.size)
				if gotSize != wantSize {
					return &NotEqualError{"size", gotSize, wantSize}
				}

				gotBuffer := got.Get()
				gotBufLen := len(gotBuffer)
				if gotBufLen != wantBufLen {
					return &NotEqualError{"len(buffer)", gotBufLen, wantBufLen}
				}
				gotBufCap := cap(gotBuffer)
				if gotBufCap != wantBufCap {
					return &NotEqualError{"cap(buffer)", gotBufCap, wantBufCap}
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &simpleBuffer{
				pool: tt.fields.pool,
				size: tt.fields.size,
			}
			b.Put(tt.args.buf)
			if err := tt.checkFunc(b); err != nil {
				t.Errorf("buffer.Put() %v", err)
				return
			}
		})
	}
}
