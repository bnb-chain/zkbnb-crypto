/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package zecrey

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveSwap(t *testing.T) {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	bEnc1, err := twistedElgamal.Enc(b1, r1, pk1)
	if err != nil {
		t.Error(err)
	}
	sk2, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(3)
	r2 := curve.RandomValue()
	bEnc2, err := twistedElgamal.Enc(b2, r2, pk2)
	if err != nil {
		t.Error(err)
	}
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
	fmt.Println("sk1:", sk1.String())
	fmt.Println("pk1:", curve.ToString(pk1))
	fmt.Println("pk2:", curve.ToString(pk2))
	fmt.Println("benc:", bEnc1.String())
	fmt.Println("receiver enc:", bEnc2.String())
	fee := big.NewInt(1)
	relationPart1, err := NewSwapRelationPart1(bEnc1, bEnc2, pk1, pk2, b1, bStarFrom, bStarTo, sk1, fromTokenId, toTokenId, fee)
	if err != nil {
		t.Error(err)
	}
	swapProofPart1, err := ProveSwapPart1(relationPart1, true)
	if err != nil {
		t.Error(err)
	}
	proofBytes := swapProofPart1.Bytes()
	proof, err := ParseSwapProofPartBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("bytes res:", res)
	part1Res, err := swapProofPart1.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, part1Res, true, "prove swap part works correctly")
	b3 := big.NewInt(8)
	r3 := curve.RandomValue()
	bEnc3, err := twistedElgamal.Enc(b3, r3, pk2)
	if err != nil {
		t.Error(err)
	}
	b4 := big.NewInt(8)
	r4 := curve.RandomValue()
	bEnc4, err := twistedElgamal.Enc(b4, r4, pk1)
	if err != nil {
		t.Error(err)
	}
	relationPart2, err := NewSwapRelationPart2(bEnc3, bEnc4, pk2, pk1, b3, sk2, fromTokenId, toTokenId, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
	swapProof, err := ProveSwapPart2(relationPart2, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
	proofBytes = swapProof.Bytes()
	swapProof, err = ParseSwapProofBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	swapProofRes, err := swapProof.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, swapProofRes, true, "swap proof works correctly")
}
