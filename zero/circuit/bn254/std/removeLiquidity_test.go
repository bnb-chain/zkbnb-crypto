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

func TestRemoveLiquidityProofConstraints_Define(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness RemoveLiquidityProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}

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
	relation, err := zero.NewRemoveLiquidityRelation(
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
	proof, err := zero.ProveRemoveLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	err = proof.AddPoolInfo(Pk_pool, B_A_Delta, B_B_Delta, b_pool_A, b_pool_B, curve.RandomValue(), curve.RandomValue())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	witness, err = SetRemoveLiquidityProofWitness(proof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
