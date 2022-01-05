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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestUnlockProof_Verify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	chainId := uint32(0)
	assetId := uint32(0)
	balance := uint64(10)
	deltaAmount := uint64(2)
	b_fee := uint64(100)
	feeEnc, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), pk)
	proof, err := ProveUnlock(
		sk, chainId, assetId, balance, deltaAmount,
		feeEnc,
		b_fee, uint32(1), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("fee enc:", feeEnc.String())
	proofStr := proof.String()
	proof2, err := ParseUnlockProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
