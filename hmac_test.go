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

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func checkEqualString(t *testing.T, output, original string) {
	if output != original {
		t.Fatalf("output != original! %#v != %#v", output, original)
	}
}

func checkNotEqualString(t *testing.T, output, original string) {
	if output == original {
		t.Fatalf("output != original! %#v != %#v", output, original)
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("012345678")
	data := []byte("hello world")

	hmac, err := HMAC("SHA1", key, data)
	if err != nil {
		t.Fatal("HMAC() failure: ", err)
	}
	hmachex := hex.EncodeToString(hmac)
	checkEqualString(t, hmachex, "e19e220122b37b708bfb95aca2577905acabf0c0")

	key = []byte("012345670")
	hmac, err = HMAC("SHA1", key, data)
	if err != nil {
		t.Fatal("HMAC() failure: ", err)
	}
	hmachex = hex.EncodeToString(hmac)
	checkNotEqualString(t, hmachex, "e19e220122b37b708bfb95aca2577905acabf0c0")
}

func TestHMACVectorsMultipart(t *testing.T) {
	algo := []string{"sha1", "sha256", "sha384", "sha512"}
	var testVector []interface{}
	json.Unmarshal(([]byte)(hashTestVectorsMultipart), &testVector)
	for _, a := range algo {
		for _, test := range testVector {
			m := test.(map[string]interface{})
			key := m["key"].(string)
			data1 := m["data1"].(string)
			data2 := m["data2"].(string)

			ctx, err := HMAC_Init(a, nil, []byte(key))
			if err != nil {
				t.Fatal("Could not get hmac context: ", err)
			}

			imd, err := ctx.HMAC_Update_ex([]byte(data1), nil)
			if err != nil {
				t.Fatal("HmacUpdate(plaintext1) failure: ", err)
			}

			ctx, err = HMAC_Init(a, nil, []byte(key))
			if err != nil {
				t.Fatal("Could not get hmac context: ", err)
			}

			_, err = ctx.HMAC_Update_ex([]byte(data2), imd)
			if err != nil {
				t.Fatal("HmacUpdate(plaintext1) failure: ", err)
			}
			hmac, err := ctx.HMAC_Final()
			if err != nil {
				t.Fatal("HmacFinal() failure: ", err)
			}
			hmachex := hex.EncodeToString(hmac)
			//t.Log(hmachex)
			checkEqualString(t, hmachex, m[a].(string))
		}
	}
}

func TestHMACVectors(t *testing.T) {
	algo := []string{"sha1", "sha256", "sha384", "sha512"}
	var testVector []interface{}
	json.Unmarshal(([]byte)(hashTestVectors), &testVector)
	for _, a := range algo {
		for _, test := range testVector {
			m := test.(map[string]interface{})
			key, _ := hex.DecodeString(m["key"].(string))
			plaintext1, _ := hex.DecodeString(m["data"].(string))

			ctx, err := HMAC_Init(a, nil, key)
			if err != nil {
				t.Fatal("Could not get hmac context: ", err)
			}

			err = ctx.HMAC_Update(plaintext1)
			if err != nil {
				t.Fatal("HmacUpdate(plaintext1) failure: ", err)
			}

			hmac, err := ctx.HMAC_Final()
			if err != nil {
				t.Fatal("HmacFinal() failure: ", err)
			}
			hmachex := hex.EncodeToString(hmac)
			checkEqualString(t, hmachex, m[a].(string))
		}
	}
}

var hashTestVectorsMultipart = `[
  {
	"key" : "012345678",
	"data1" : "hello world",
	"data2" : "hello world again",
	"sha1" : "ae80942e9790594ba0074308a58c524e97617f66",
	"sha256" : "2cf1b0095941f6821b333be8fbec57ccda65113915d6288da6e00b0c7e1fcabd",
	"sha384" : "cbe5e006212f6514ea20b03a16118eebf879cf3139b949f23bec170ffd54a95e83de85c78261d9b46c163d260ec84951",
	"sha512" : "492d7b7a927a9ac1f50379aa4631893048039ae8644147a2f2bc32993297518c591175e8d112c194d7a5357836d992bc245f8293f939cca35a3b19a18970057b"
  }
]`

var hashTestVectors = `[
  {
    "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "data": "4869205468657265",
    "DSA": "b617318655057264e28bc0b6fb378c8ef146be00",
    "DSA-SHA": "b617318655057264e28bc0b6fb378c8ef146be00",
    "DSA-SHA1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "DSA-SHA1-old": "b617318655057264e28bc0b6fb378c8ef146be00",
    "RSA-MD4": "5570ce964ba8c11756cdc3970278ff5a",
    "RSA-MD5": "5ccec34ea9656392457fa1ac27f08fbc",
    "RSA-MDC2": "29a31e52f653c7cdde218cc1b53b3a6b",
    "RSA-RIPEMD160": "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    "RSA-SHA": "c2cbaa7817447fb494ca153a88f2f013f934ff58",
    "RSA-SHA1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "RSA-SHA1-2": "b617318655057264e28bc0b6fb378c8ef146be00",
    "RSA-SHA224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    "RSA-SHA256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "RSA-SHA384": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    "RSA-SHA512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    "dsaEncryption": "b617318655057264e28bc0b6fb378c8ef146be00",
    "dsaWithSHA": "b617318655057264e28bc0b6fb378c8ef146be00",
    "dsaWithSHA1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "dss1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "ecdsa-with-SHA1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "md4": "5570ce964ba8c11756cdc3970278ff5a",
    "md4WithRSAEncryption": "5570ce964ba8c11756cdc3970278ff5a",
    "md5": "5ccec34ea9656392457fa1ac27f08fbc",
    "md5WithRSAEncryption": "5ccec34ea9656392457fa1ac27f08fbc",
    "mdc2": "29a31e52f653c7cdde218cc1b53b3a6b",
    "mdc2WithRSA": "29a31e52f653c7cdde218cc1b53b3a6b",
    "ripemd": "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    "ripemd160": "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    "ripemd160WithRSA": "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    "rmd160": "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    "sha": "c2cbaa7817447fb494ca153a88f2f013f934ff58",
    "sha1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "sha1WithRSAEncryption": "b617318655057264e28bc0b6fb378c8ef146be00",
    "sha224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    "sha224WithRSAEncryption": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    "sha256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "sha256WithRSAEncryption": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "sha384": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    "sha384WithRSAEncryption": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    "sha512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    "sha512WithRSAEncryption": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    "shaWithRSAEncryption": "c2cbaa7817447fb494ca153a88f2f013f934ff58",
    "ssl2-md5": "5ccec34ea9656392457fa1ac27f08fbc",
    "ssl3-md5": "5ccec34ea9656392457fa1ac27f08fbc",
    "ssl3-sha1": "b617318655057264e28bc0b6fb378c8ef146be00",
    "whirlpool": "8a2c9b1ccf4b28660de78af9db15b7c94d129ec960ca9a950a665ea5e88362e24f4474354e18512d956d9bb7e6bbbb50b9ba0d3093b0a17c6ec2aa91e57169ce"
  },
  {
    "key": "4a656665",
    "data": "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
    "DSA": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "DSA-SHA": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "DSA-SHA1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "DSA-SHA1-old": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "RSA-MD4": "c8451e320690b9b5dbd859f2eb63230b",
    "RSA-MD5": "f1bbf62a07a5ea3e72072d12e9e25014",
    "RSA-MDC2": "dbd93391e735e2c1cb9621922a45246f",
    "RSA-RIPEMD160": "c15633df3b0940bb067d0c25f3da75c5293da6d6",
    "RSA-SHA": "b058879503487b824bfb6bdd59d10e910f55a428",
    "RSA-SHA1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "RSA-SHA1-2": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "RSA-SHA224": "4cd18ac6b4a70fda4033f69d458a8e0d653c650e4cb5db6b459f7bae",
    "RSA-SHA256": "83038173da2181cc0c8c0f92e79c4810e33a6aaad6d09c127cda8cb29d10b734",
    "RSA-SHA384": "48fddfdb6f932f923ac9a4114187231129a808f7499c267ec62e633e60bc8261d3b567d60bbb1bed95bd62d740807ef2",
    "RSA-SHA512": "e16a6a4a714522a20467f345e6bfb1464b922eaa7c3c6e8db1b1cad2ad97f18ec2893adf7c163b701c93f83e4e86cb788f383a3284825445c42bc4741beb675b",
    "dsaEncryption": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "dsaWithSHA": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "dsaWithSHA1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "dss1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "ecdsa-with-SHA1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "md4": "c8451e320690b9b5dbd859f2eb63230b",
    "md4WithRSAEncryption": "c8451e320690b9b5dbd859f2eb63230b",
    "md5": "f1bbf62a07a5ea3e72072d12e9e25014",
    "md5WithRSAEncryption": "f1bbf62a07a5ea3e72072d12e9e25014",
    "mdc2": "dbd93391e735e2c1cb9621922a45246f",
    "mdc2WithRSA": "dbd93391e735e2c1cb9621922a45246f",
    "ripemd": "c15633df3b0940bb067d0c25f3da75c5293da6d6",
    "ripemd160": "c15633df3b0940bb067d0c25f3da75c5293da6d6",
    "ripemd160WithRSA": "c15633df3b0940bb067d0c25f3da75c5293da6d6",
    "rmd160": "c15633df3b0940bb067d0c25f3da75c5293da6d6",
    "sha": "b058879503487b824bfb6bdd59d10e910f55a428",
    "sha1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "sha1WithRSAEncryption": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "sha224": "4cd18ac6b4a70fda4033f69d458a8e0d653c650e4cb5db6b459f7bae",
    "sha224WithRSAEncryption": "4cd18ac6b4a70fda4033f69d458a8e0d653c650e4cb5db6b459f7bae",
    "sha256": "83038173da2181cc0c8c0f92e79c4810e33a6aaad6d09c127cda8cb29d10b734",
    "sha256WithRSAEncryption": "83038173da2181cc0c8c0f92e79c4810e33a6aaad6d09c127cda8cb29d10b734",
    "sha384": "48fddfdb6f932f923ac9a4114187231129a808f7499c267ec62e633e60bc8261d3b567d60bbb1bed95bd62d740807ef2",
    "sha384WithRSAEncryption": "48fddfdb6f932f923ac9a4114187231129a808f7499c267ec62e633e60bc8261d3b567d60bbb1bed95bd62d740807ef2",
    "sha512": "e16a6a4a714522a20467f345e6bfb1464b922eaa7c3c6e8db1b1cad2ad97f18ec2893adf7c163b701c93f83e4e86cb788f383a3284825445c42bc4741beb675b",
    "sha512WithRSAEncryption": "e16a6a4a714522a20467f345e6bfb1464b922eaa7c3c6e8db1b1cad2ad97f18ec2893adf7c163b701c93f83e4e86cb788f383a3284825445c42bc4741beb675b",
    "shaWithRSAEncryption": "b058879503487b824bfb6bdd59d10e910f55a428",
    "ssl2-md5": "f1bbf62a07a5ea3e72072d12e9e25014",
    "ssl3-md5": "f1bbf62a07a5ea3e72072d12e9e25014",
    "ssl3-sha1": "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f",
    "whirlpool": "2711355e35e73b3dc260c045aa3b1865231640f9373ed99eb4df267953498263ad06fd7ad57243cca7a5400c730b240c828bc4710b8f225516416e0723f9c1ae"
  },
  {
    "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "data": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "DSA": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "DSA-SHA": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "DSA-SHA1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "DSA-SHA1-old": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "RSA-MD4": "bc9d1ec8a7d0ee67a2955fac8cc78dde",
    "RSA-MD5": "2ab8b9a9f7d3894d15ad8383b97044b2",
    "RSA-MDC2": "5ab7d84959d9dd223b312bd7cea84f2c",
    "RSA-RIPEMD160": "b0b105360de759960ab4f35298e116e295d8e7c1",
    "RSA-SHA": "20b8027a3e4b3a7485d16d3297ea05389d64b4bf",
    "RSA-SHA1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "RSA-SHA1-2": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "RSA-SHA224": "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
    "RSA-SHA256": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "RSA-SHA384": "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
    "RSA-SHA512": "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    "dsaEncryption": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "dsaWithSHA": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "dsaWithSHA1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "dss1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "ecdsa-with-SHA1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "md4": "bc9d1ec8a7d0ee67a2955fac8cc78dde",
    "md4WithRSAEncryption": "bc9d1ec8a7d0ee67a2955fac8cc78dde",
    "md5": "2ab8b9a9f7d3894d15ad8383b97044b2",
    "md5WithRSAEncryption": "2ab8b9a9f7d3894d15ad8383b97044b2",
    "mdc2": "5ab7d84959d9dd223b312bd7cea84f2c",
    "mdc2WithRSA": "5ab7d84959d9dd223b312bd7cea84f2c",
    "ripemd": "b0b105360de759960ab4f35298e116e295d8e7c1",
    "ripemd160": "b0b105360de759960ab4f35298e116e295d8e7c1",
    "ripemd160WithRSA": "b0b105360de759960ab4f35298e116e295d8e7c1",
    "rmd160": "b0b105360de759960ab4f35298e116e295d8e7c1",
    "sha": "20b8027a3e4b3a7485d16d3297ea05389d64b4bf",
    "sha1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "sha1WithRSAEncryption": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "sha224": "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
    "sha224WithRSAEncryption": "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
    "sha256": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "sha256WithRSAEncryption": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "sha384": "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
    "sha384WithRSAEncryption": "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
    "sha512": "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    "sha512WithRSAEncryption": "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    "shaWithRSAEncryption": "20b8027a3e4b3a7485d16d3297ea05389d64b4bf",
    "ssl2-md5": "2ab8b9a9f7d3894d15ad8383b97044b2",
    "ssl3-md5": "2ab8b9a9f7d3894d15ad8383b97044b2",
    "ssl3-sha1": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    "whirlpool": "ea252f252e230e3d1950cf44679e31d9de70d1dec6f41dbe38a12d76e2b54cffa2637f0408a48a0a387315ef1118055d373dc295bba3563276f846a0957fb823"
  },
  {
    "key": "0102030405060708090a0b0c0d0e0f10111213141516171819",
    "data": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    "DSA": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "DSA-SHA": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "DSA-SHA1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "DSA-SHA1-old": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "RSA-MD4": "fb14cddf9efe11ad24033fc70f37bb9e",
    "RSA-MD5": "697eaf0aca3a3aea3a75164746ffaa79",
    "RSA-MDC2": "b9a41751dc30db9044be3614f1aea74f",
    "RSA-RIPEMD160": "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
    "RSA-SHA": "8e47262e2e939da3cd487ddffe3f6bbb9f2809e7",
    "RSA-SHA1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "RSA-SHA1-2": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "RSA-SHA224": "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
    "RSA-SHA256": "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    "RSA-SHA384": "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
    "RSA-SHA512": "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    "dsaEncryption": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "dsaWithSHA": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "dsaWithSHA1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "dss1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "ecdsa-with-SHA1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "md4": "fb14cddf9efe11ad24033fc70f37bb9e",
    "md4WithRSAEncryption": "fb14cddf9efe11ad24033fc70f37bb9e",
    "md5": "697eaf0aca3a3aea3a75164746ffaa79",
    "md5WithRSAEncryption": "697eaf0aca3a3aea3a75164746ffaa79",
    "mdc2": "b9a41751dc30db9044be3614f1aea74f",
    "mdc2WithRSA": "b9a41751dc30db9044be3614f1aea74f",
    "ripemd": "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
    "ripemd160": "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
    "ripemd160WithRSA": "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
    "rmd160": "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
    "sha": "8e47262e2e939da3cd487ddffe3f6bbb9f2809e7",
    "sha1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "sha1WithRSAEncryption": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "sha224": "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
    "sha224WithRSAEncryption": "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
    "sha256": "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    "sha256WithRSAEncryption": "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    "sha384": "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
    "sha384WithRSAEncryption": "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
    "sha512": "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    "sha512WithRSAEncryption": "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    "shaWithRSAEncryption": "8e47262e2e939da3cd487ddffe3f6bbb9f2809e7",
    "ssl2-md5": "697eaf0aca3a3aea3a75164746ffaa79",
    "ssl3-md5": "697eaf0aca3a3aea3a75164746ffaa79",
    "ssl3-sha1": "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    "whirlpool": "35bc33e2ed71e1cb01c140ddd3291ae3f84e9f0dce18005a1123df199983a211fe744b244449a1c093b17584069359bc6a95352271d78e2ef7a6f21dc28ab3c1"
  },
  {
    "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "data": "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
    "DSA": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "DSA-SHA": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "DSA-SHA1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "DSA-SHA1-old": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "RSA-MD4": "7d3124db88aaddd70a5d1dcd1a1a9113",
    "RSA-MD5": "09b8ae7b15adbbb243aca3491b51512b",
    "RSA-MDC2": "d0efb0ded6e4b72a69fdd4ba1b3746b4",
    "RSA-RIPEMD160": "1ed106e5a8ef0a90efa3beb06b391e8693cd3137",
    "RSA-SHA": "8b0a2731db7a6c716644354dbebdf8f4b0eb4e1f",
    "RSA-SHA1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "RSA-SHA1-2": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "RSA-SHA224": "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
    "RSA-SHA256": "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    "RSA-SHA384": "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
    "RSA-SHA512": "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    "dsaEncryption": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "dsaWithSHA": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "dsaWithSHA1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "dss1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "ecdsa-with-SHA1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "md4": "7d3124db88aaddd70a5d1dcd1a1a9113",
    "md4WithRSAEncryption": "7d3124db88aaddd70a5d1dcd1a1a9113",
    "md5": "09b8ae7b15adbbb243aca3491b51512b",
    "md5WithRSAEncryption": "09b8ae7b15adbbb243aca3491b51512b",
    "mdc2": "d0efb0ded6e4b72a69fdd4ba1b3746b4",
    "mdc2WithRSA": "d0efb0ded6e4b72a69fdd4ba1b3746b4",
    "ripemd": "1ed106e5a8ef0a90efa3beb06b391e8693cd3137",
    "ripemd160": "1ed106e5a8ef0a90efa3beb06b391e8693cd3137",
    "ripemd160WithRSA": "1ed106e5a8ef0a90efa3beb06b391e8693cd3137",
    "rmd160": "1ed106e5a8ef0a90efa3beb06b391e8693cd3137",
    "sha": "8b0a2731db7a6c716644354dbebdf8f4b0eb4e1f",
    "sha1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "sha1WithRSAEncryption": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "sha224": "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
    "sha224WithRSAEncryption": "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
    "sha256": "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    "sha256WithRSAEncryption": "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    "sha384": "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
    "sha384WithRSAEncryption": "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
    "sha512": "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    "sha512WithRSAEncryption": "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    "shaWithRSAEncryption": "8b0a2731db7a6c716644354dbebdf8f4b0eb4e1f",
    "ssl2-md5": "09b8ae7b15adbbb243aca3491b51512b",
    "ssl3-md5": "09b8ae7b15adbbb243aca3491b51512b",
    "ssl3-sha1": "217e44bb08b6e06a2d6c30f3cb9f537f97c63356",
    "whirlpool": "1dec7ddb9e826b04c5c033a7e156415e830eb8fca4958c83ba1a1c1cac0c4f1c8a6bacf41b18a380f59b6832e4ccb571b7fd27e6e2688bcaf180e4adca24c228"
  }
]`
