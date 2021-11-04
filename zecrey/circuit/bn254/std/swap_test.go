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

func TestSwapProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness SwapProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 1; i++ {
		b_u_A := uint64(8)
		b_u_fee := uint64(4)
		assetAId := uint32(1)
		assetBId := uint32(2)
		assetFeeId := uint32(3)
		b_A_Delta := uint64(1)
		b_B_Delta := uint64(2)
		b_fee_Delta := uint64(1)
		b_Dao_A := uint64(10)
		b_Dao_B := uint64(10)
		feeRate := uint32(3)
		sk_u, Pk_u := twistedElgamal.GenKeyPair()
		_, Pk_Dao := twistedElgamal.GenKeyPair()
		C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
		C_ufee, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_fee)), curve.RandomValue(), Pk_u)
		relation, err := zecrey.NewSwapRelation(
			C_uA, C_ufee,
			Pk_Dao, Pk_u,
			assetAId, assetBId, assetFeeId,
			b_A_Delta, b_B_Delta, b_fee_Delta, b_u_A, b_u_fee,
			feeRate,
			sk_u,
		)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := zecrey.ProveSwap(relation)
		if err != nil {
			t.Fatal(err)
		}
		// set params
		proof.AddDaoInfo(b_Dao_A, b_Dao_B)
		witness, err = SetSwapProofWitness(proof, true)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("constraints:", r1cs.GetNbConstraints())
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
	}
}
