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
#include <openssl/sha.h>
*/
import "C"

import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"
)

type hmacCtxSt struct {
	hCtx *C.HMAC_CTX
}

type hmacCtx struct {
	*hmacCtxSt
}

type HmacCtx interface {
	HMAC_Update(data []byte) error
	HMAC_Update_ex(data, pmd []byte) ([]byte, error)
	HMAC_Final() ([]byte, error)
	hmacContext() *C.HMAC_CTX
	evpMd() *C.EVP_MD
	evpMdCtx() *C.EVP_MD_CTX
	mdData() []byte
	setMdData(pmd []byte)
	getMdCtxSize() int
}

// Following the memory allocation/free pattern used elsewhere
// within spacemonkey lib
func newHmacCtx() (*hmacCtxSt, error) {
	//fmt.Println("allocating hmac context")
	var ptr C.HMAC_CTX
	hctx := (*C.HMAC_CTX)(C.malloc(C.size_t(unsafe.Sizeof(ptr))))

	C.HMAC_CTX_init(hctx)
	if hctx == nil {
		return nil, fmt.Errorf("failed to allocate hmac context")
	}
	hctx.md_ctx.md_data = nil
	ctx := &hmacCtxSt{hctx}
	runtime.SetFinalizer(ctx, func(ctx *hmacCtxSt) {
		//fmt.Println("Cleanup hmac context")
		C.HMAC_CTX_cleanup(ctx.hCtx)
		if ctx.hCtx != nil {
			//fmt.Println("Freeing hmac context")
			C.free(unsafe.Pointer(ctx.hCtx))
		}
	})

	return ctx, nil
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

func (ctx *hmacCtx) hmacContext() *C.HMAC_CTX {
	return ctx.hmacCtxSt.hCtx
}

func (ctx *hmacCtx) evpMd() *C.EVP_MD {
	return ctx.hmacCtxSt.hCtx.md
}

func (ctx *hmacCtx) evpMdCtx() *C.EVP_MD_CTX {
	return &ctx.hmacCtxSt.hCtx.md_ctx
}

func (ctx *hmacCtx) getMdCtxSize() int {
	var mdCtxSize uintptr
	mdSize := C.EVP_MD_size(ctx.evpMd())
	if mdSize == C.SHA_DIGEST_LENGTH {
		var sha_ctx C.SHA_CTX
		mdCtxSize = unsafe.Sizeof(sha_ctx)
	} else if mdSize == C.SHA256_DIGEST_LENGTH {
		var sha_ctx C.SHA256_CTX
		mdCtxSize = unsafe.Sizeof(sha_ctx)
	} else if mdSize == C.SHA384_DIGEST_LENGTH || mdSize == C.SHA512_DIGEST_LENGTH {
		var sha_ctx C.SHA512_CTX
		mdCtxSize = unsafe.Sizeof(sha_ctx)
	}
	return int(mdCtxSize)
}

func (ctx *hmacCtx) mdData() []byte {
	outlen := ctx.getMdCtxSize()
	outbuf := make([]byte, outlen)
	md_ctx := ctx.evpMdCtx()
	slice := &reflect.SliceHeader{Data: uintptr(md_ctx.md_data), Len: int(outlen), Cap: int(outlen)}
	rbuf := *(*[]byte)(unsafe.Pointer(slice))
	copy(outbuf, rbuf)
	return outbuf[:len(outbuf)]
}

func (ctx *hmacCtx) setMdData(pmd []byte) {
	outlen := ctx.getMdCtxSize()
	md_ctx := ctx.evpMdCtx()
	slice := &reflect.SliceHeader{Data: uintptr(md_ctx.md_data), Len: int(outlen), Cap: int(outlen)}
	rbuf := *(*[]byte)(unsafe.Pointer(slice))
	copy(rbuf, pmd)
}

func HMAC_Init(d string, e *Engine, key []byte) (HmacCtx, error) {
	return hmacInit(d, e, key)
}

func (ctx *hmacCtx) HMAC_Update(data []byte) error {
	if 1 != C.HMAC_Update(ctx.hmacContext(), (*C.uchar)(&data[0]), C.size_t(len(data))) {
		return fmt.Errorf("failed hmac update")
	}

	return nil
}

func (ctx *hmacCtx) HMAC_Update_ex(data, imd []byte) ([]byte, error) {
	if imd != nil {
		//fmt.Println("Setting intermediate hash")
		ctx.setMdData(imd)
	}
	if 1 != C.HMAC_Update(ctx.hmacContext(), (*C.uchar)(&data[0]), C.size_t(len(data))) {
		return nil, fmt.Errorf("failed hmac update")
	}

	return ctx.mdData(), nil
}

func (ctx *hmacCtx) HMAC_Final() ([]byte, error) {
	outbuf := make([]byte, C.EVP_MD_size(ctx.evpMd()))
	outlen := C.uint(len(outbuf))
	if 1 != C.HMAC_Final(ctx.hmacContext(), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, fmt.Errorf("failed hmac final")
	}
	// Force garbage collection?
	runtime.GC()

	return outbuf[:outlen], nil
}

func HMAC(d string, key, data []byte) ([]byte, error) {
	// Get EVP_MD for the given algorithm name
	cname := C.CString(d)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, fmt.Errorf("Digest %v not found", d)
	}

	// Allocate out buffer
	outbuf := make([]byte, C.EVP_MD_size(md))
	outlen := C.uint(len(outbuf))

	keyBytes := (unsafe.Pointer)(&key[0])
	keyLen := C.int(len(key))
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to process")
	}
	if nil == C.HMAC(md, keyBytes, keyLen, (*C.uchar)(&data[0]), C.size_t(len(data)), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, fmt.Errorf("failed to create hmac")
	}

	return outbuf[:outlen], nil
}
