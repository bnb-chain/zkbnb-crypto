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
	bEnc, err := twistedElgamal.Enc(b1, r1, pk1)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
	fmt.Println("sk1:", sk1.String())
	fmt.Println("pk1:", curve.ToString(pk1))
	fmt.Println("benc:", bEnc.String())
	relationPart1, err := NewSwapRelationPart1(bEnc, pk1, bStarFrom, bStarTo, sk1, fromTokenId, toTokenId)
	if err != nil {
		t.Error(err)
	}
	swapProofPart1, err := ProveSwapPart1(relationPart1, true)
	if err != nil {
		t.Error(err)
	}
	part1Res, err := swapProofPart1.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, part1Res, true, "prove swap part works correctly")
	sk2, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(8)
	r2 := curve.RandomValue()
	bEnc2, err := twistedElgamal.Enc(b2, r2, pk2)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	relationPart2, err := NewSwapRelationPart2(bEnc2, pk2, sk2, fromTokenId, toTokenId, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
	swapProof, err := ProveSwapPart2(relationPart2, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
	swapProofRes, err := swapProof.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, swapProofRes, true, "swap proof works correctly")
}
