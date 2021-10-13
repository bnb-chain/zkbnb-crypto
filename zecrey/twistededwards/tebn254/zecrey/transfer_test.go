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

func TestCorrectInfoProve(t *testing.T) {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := uint64(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(big.NewInt(int64(b1)), r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("sk1:", sk1.String())
	fmt.Println("pk1:", curve.ToString(pk1))
	fmt.Println("pk2:", curve.ToString(pk2))
	fmt.Println("pk3:", curve.ToString(pk3))
	fmt.Println("b1Enc:", b1Enc.String())
	fmt.Println("b2Enc:", b2Enc.String())
	fmt.Println("b3Enc:", b3Enc.String())
	elapse := time.Now()
	fee := uint64(1)
	relation, err := NewTransferProofRelation(1, fee)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b2Enc, pk2, 0, 2, nil)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b1Enc, pk1, b1, -5, sk1)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b3Enc, pk3, 0, 2, nil)
	if err != nil {
		t.Error(err)
	}
	proof, err := ProveTransfer(relation)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	elapse = time.Now()
	proofStr := proof.String()
	proof2, err := ParseTransferProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Error(err)
	}
	fmt.Println("verify time:", time.Since(elapse))
	assert.Equal(t, true, res, "invalid proof")
}
