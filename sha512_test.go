// Copyright (C) 2014 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build cgo

package openssl

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
	"testing"
)

func TestSHA512(t *testing.T) {
	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		expected := sha512.Sum512(buf)
		got, err := SHA512(buf)
		if err != nil {
			t.Fatal(err)
		}

		if expected != got {
			t.Fatal("exp:%x got:%x", expected, got)
		}
	}
}

func TestSHA512Writer(t *testing.T) {
	ohash, err := NewSHA512Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha512.New()

	for i := 0; i < 100; i++ {
		if err := ohash.Reset(); err != nil {
			t.Fatal(err)
		}
		hash.Reset()
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		if _, err := ohash.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := hash.Write(buf); err != nil {
			t.Fatal(err)
		}

		var got, exp [64]byte

		hash.Sum(exp[:0])
		got, err := ohash.Sum()
		if err != nil {
			t.Fatal(err)
		}

		if got != exp {
			t.Fatal("exp:%x got:%x", exp, got)
		}
	}
}

func benchmarkSHA512(b *testing.B, length int64, fn shafunc) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(buf)
	}
}

func BenchmarkSHA512Large_openssl(b *testing.B) {
	benchmarkSHA512(b, 1024*1024, func(buf []byte) { SHA512(buf) })
}

func BenchmarkSHA512Large_stdlib(b *testing.B) {
	benchmarkSHA512(b, 1024*1024, func(buf []byte) { sha512.Sum512(buf) })
}

func BenchmarkSHA512Small_openssl(b *testing.B) {
	benchmarkSHA512(b, 1, func(buf []byte) { SHA512(buf) })
}

func BenchmarkSHA512Small_stdlib(b *testing.B) {
	benchmarkSHA512(b, 1, func(buf []byte) { sha512.Sum512(buf) })
}
