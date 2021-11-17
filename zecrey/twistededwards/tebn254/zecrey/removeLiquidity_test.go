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
	"gotest.tools/assert"
	"log"
	"math/big"
	"testing"
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestRemoveLiquidityProof_Verify(t *testing.T) {
	//b_u_A := uint64(8)
	//b_u_B := uint64(4)
	B_LP := uint64(100)
	assetAId := uint32(1)
	assetBId := uint32(2)
	B_A_Delta := uint64(10)
	B_B_Delta := uint64(10)
	MinB_A_Delta := uint64(1)
	MinB_B_Delta := uint64(1)
	Delta_LP := uint64(10)
	b_pool_A := uint64(1000)
	b_pool_B := uint64(1000)
	Sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	//C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	//C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	C_u_LP, _ := twistedElgamal.Enc(big.NewInt(int64(B_LP)), curve.RandomValue(), Pk_u)
	// fee
	B_fee := uint64(100)
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(B_fee)), curve.RandomValue(), Pk_u)
	GasFeeAssetId := uint32(1)
	GasFee := uint64(1)
	relation, err := NewRemoveLiquidityRelation(
		C_u_LP,
		Pk_u,
		B_LP,
		Delta_LP,
		MinB_A_Delta, MinB_B_Delta,
		assetAId, assetBId,
		Sk_u,
		// fee part
		C_fee, B_fee, GasFeeAssetId, GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveRemoveLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	err = proof.AddPoolInfo(Pk_pool, B_A_Delta, B_B_Delta, b_pool_A, b_pool_B, curve.RandomValue(), curve.RandomValue())
	if err != nil {
		t.Fatal(err)
	}
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseRemoveLiquidityProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
