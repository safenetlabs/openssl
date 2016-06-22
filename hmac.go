// Copyright (C) 2016 Gemalto
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

// +build cgo,!darwin cgo,brew

package openssl

/*
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int EVP_MD_size_not_a_macro(EVP_MD *md) {
	return EVP_MD_size(md);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type hmacCtxSt struct {
	hCtx *C.HMAC_CTX
}

func newHmacCtx() (*hmacCtxSt, error) {
	//fmt.Println("allocating hmac context")
	var ptr C.HMAC_CTX
	hctx := (*C.HMAC_CTX)(C.malloc(C.size_t(unsafe.Sizeof(ptr))))
	C.HMAC_CTX_init(hctx)
	if hctx == nil {
		return nil, fmt.Errorf("failed to allocate hmac context")
	}
	ctx := &hmacCtxSt{hctx}
	runtime.SetFinalizer(ctx, func(ctx *hmacCtxSt) {
		//fmt.Println("Freeing hmac context")
		C.HMAC_CTX_cleanup(ctx.hCtx)
	})

	return ctx, nil
}

type hmacCtx struct {
	*hmacCtxSt
}

func hmacInit(name string, e *Engine, key []byte) (*hmacCtx, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, fmt.Errorf("Digest %v not found", name)
	}
	ctx, err := newHmacCtx()
	if err != nil {
		return nil, err
	}
	var eptr *C.ENGINE = nil
	if e != nil {
		eptr = e.e
	}
	keyBytes := (unsafe.Pointer)(&key[0])
	keyLen := C.int(len(key))
	C.HMAC_Init_ex(ctx.hCtx, keyBytes, keyLen, md, eptr)
	return &hmacCtx{hmacCtxSt: ctx}, nil
}

type HmacCtx interface {
	HmacUpdate(input []byte) error
	HmacFinal() ([]byte, error)
	hmacContext() *C.HMAC_CTX
	mdContext() *C.EVP_MD
}

func HmacInit(d string, e *Engine, key []byte) (HmacCtx, error) {
	return hmacInit(d, e, key)
}

func (ctx *hmacCtx) hmacContext() *C.HMAC_CTX {
	return ctx.hmacCtxSt.hCtx
}

func (ctx *hmacCtx) mdContext() *C.EVP_MD {
	return ctx.hmacCtxSt.hCtx.md
}

func (ctx *hmacCtx) HmacUpdate(input []byte) error {
	if 1 != C.HMAC_Update(ctx.hmacContext(), (*C.uchar)(&input[0]), C.size_t(len(input))) {
		return fmt.Errorf("failed hmac update")
	}

	return nil
}

func (ctx *hmacCtx) HmacFinal() ([]byte, error) {
	outbuf := make([]byte, C.EVP_MD_size_not_a_macro(ctx.mdContext()))
	outlen := C.uint(len(outbuf))
	if 1 != C.HMAC_Final(ctx.hmacContext(), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, fmt.Errorf("failed hmac final")
	}
	// Force garbage collection
	runtime.GC()

	return outbuf[:outlen], nil
}
