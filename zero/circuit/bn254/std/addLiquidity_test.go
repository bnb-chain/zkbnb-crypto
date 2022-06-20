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

package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"math/big"
	"testing"
)

func TestAddLiquidityProofConstraints_Define(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness AddLiquidityProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	b_uA := uint64(300)
	b_uB := uint64(200)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(3)
	b_B_Delta := uint64(26)
	b_Dao_A := uint64(10)
	b_Dao_B := uint64(100)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_uA)), curve.RandomValue(), Pk_u)
	C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_uB)), curve.RandomValue(), Pk_u)
	b_fee := uint64(100)
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), Pk_u)
	GasFeeAssetId := uint32(3)
	GasFee := uint64(10)
	relation, err := zero.NewAddLiquidityRelation(
		C_uA, C_uB,
		Pk_pool, Pk_u,
		assetAId, assetBId,
		b_uA, b_uB,
		b_A_Delta, b_B_Delta,
		sk_u,
		// fee part
		C_fee, b_fee, GasFeeAssetId, GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zero.ProveAddLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddPoolInfo(b_Dao_A, b_Dao_B)
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	witness, err = SetAddLiquidityProofWitness(proof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
