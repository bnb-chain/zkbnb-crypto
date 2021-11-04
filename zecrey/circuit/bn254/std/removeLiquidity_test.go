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
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestRemoveLiquidityProofConstraints_Define(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness RemoveLiquidityProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}

	b_u_LP := uint64(1)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(1)
	Delta_LP := uint64(1)
	b_Dao_A := uint64(100)
	b_Dao_B := uint64(100)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	//C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	//C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	C_uLP, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_LP)), curve.RandomValue(), Pk_u)
	relation, err := zecrey.NewRemoveLiquidityRelation(
		C_uLP,
		Pk_Dao, Pk_u,
		b_u_LP,
		Delta_LP,
		b_A_Delta, b_B_Delta,
		assetAId, assetBId,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveRemoveLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddDaoInfo(b_Dao_A, b_Dao_B, curve.RandomValue(), curve.RandomValue())
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	witness, err = SetRemoveLiquidityProofWitness(proof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}
