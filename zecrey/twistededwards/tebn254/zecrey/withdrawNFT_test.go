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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"gotest.tools/assert"
	"math/big"
	"testing"
	"time"
)

func TestWithdrawNftProof_Verify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	r := curve.RandomValue()
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc2:", bEnc2.String())
	//feeAssetId := uint32(2)
	hFunc := zmimc.Hmimc
	hFunc.Write([]byte("test data"))
	contentHash := hFunc.Sum(nil)
	receiverAddr := "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171"
	relation, err := NewWithdrawNftRelation(
		pk, 9, contentHash, receiverAddr, 1, sk, bEnc2, b_fee, 1, fee,
	)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
	withdrawProof, err := ProveWithdrawNft(relation)
	if err != nil {
		t.Error(err)
	}
	proofStr := withdrawProof.String()
	proof, err := ParseWithdrawNftProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "mintNft proof works incorrectly")
}
