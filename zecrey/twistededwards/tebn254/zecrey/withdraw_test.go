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
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveWithdraw(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	b := uint64(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
	if err != nil {
		t.Error(err)
	}
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	bStar := uint64(2)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
	fmt.Println("benc2:", bEnc2.String())
	addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
	assetId := uint32(1)
	feeAssetId := uint32(2)
	relation, err := NewWithdrawRelation(
		1,
		bEnc,
		pk,
		b, bStar,
		sk,
		assetId, addr,
		bEnc2, b_fee, feeAssetId, fee,
	)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
	proofStr := withdrawProof.String()
	proof, err := ParseWithdrawProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "withdraw proof works correctly")
}

func TestProveWithdrawSameFee(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	b := uint64(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
	if err != nil {
		t.Error(err)
	}
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	bStar := uint64(2)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
	fmt.Println("benc2:", bEnc2.String())
	addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
	assetId := uint32(1)
	//feeAssetId := uint32(2)
	relation, err := NewWithdrawRelation(
		1,
		bEnc,
		pk,
		b, bStar,
		sk,
		assetId, addr,
		bEnc, b, assetId, fee,
	)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
	proofStr := withdrawProof.String()
	proof, err := ParseWithdrawProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "withdraw proof works correctly")
}
