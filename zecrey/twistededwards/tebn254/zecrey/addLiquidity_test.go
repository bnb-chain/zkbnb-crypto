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

func TestAddLiquidityProof_Verify(t *testing.T) {
	b_u_A := uint64(8)
	b_u_B := uint64(4)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(1)
	b_Dao_A := uint64(10)
	b_Dao_B := uint64(10)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	relation, err := NewAddLiquidityRelation(
		C_uA, C_uB,
		Pk_Dao, Pk_u,
		assetAId, assetBId,
		b_u_A, b_u_B,
		b_A_Delta, b_B_Delta,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveAddLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddDaoInfo(b_Dao_A, b_Dao_B)
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseAddLiquidityProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
