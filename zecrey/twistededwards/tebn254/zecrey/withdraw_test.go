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
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveWithdraw(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	if err != nil {
		t.Error(err)
	}
	bStar := big.NewInt(2)
	fee := big.NewInt(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
	addr := "0x99AC8881834797ebC32f185ee27c2e96842e1a47"
	relation, err := NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1, addr, fee)
	if err != nil {
		t.Error(err)
	}
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
	proofBytes, err := json.Marshal(withdrawProof)
	if err != nil {
		t.Error(err)
	}
	var proof *WithdrawProof
	err = json.Unmarshal(proofBytes, &proof)
	if err != nil {
		t.Error(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	proofBytes = proof.Bytes()
	proof, err = ParseWithdrawProofBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	res, err = proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	proofStr := proof.String()
	proof, err = ParseWithdrawProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err = proof.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, res, true, "withdraw proof works correctly")
	if res {
		bEnc.CR.Add(bEnc.CR, relation.CRStar)
		decVal, err := twistedElgamal.Dec(bEnc, sk, 100)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, decVal.String(), "5", "withdraw works correctly")
		fmt.Println(decVal)
	}
}
