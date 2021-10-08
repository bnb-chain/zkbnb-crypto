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
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestSwapProof2_Verify(t *testing.T) {
	b_u_A := uint32(8)
	b_u_fee := uint32(4)
	assetAId := uint32(1)
	assetBId := uint32(2)
	assetFeeId := uint32(3)
	b_A_Delta := uint32(1)
	b_B_Delta := uint32(2)
	b_fee_Delta := uint32(1)
	b_Dao_A := uint32(10)
	b_Dao_B := uint32(10)
	feeRate := uint32(3)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	C_ufee, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_fee)), curve.RandomValue(), Pk_u)
	relation, err := NewSwapRelation(
		C_uA, C_ufee,
		Pk_Dao, Pk_u,
		assetAId, assetBId, assetFeeId,
		b_A_Delta, b_B_Delta, b_fee_Delta, b_u_A, b_u_fee,
		b_Dao_A, b_Dao_B,
		feeRate,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveSwap(relation)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}
