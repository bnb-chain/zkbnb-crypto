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
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

func TestComRangeProofCircuit_Success(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness ComRangeProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1; i++ {
		b := big.NewInt(-1)
		var rs [RangeMaxBits]*big.Int
		r := big.NewInt(0)
		for i := 0; i < RangeMaxBits; i++ {
			rs[i] = curve.RandomValue()
			r.Add(r, rs[i])
		}
		r.Mod(r, curve.Order)
		g := curve.H
		h := curve.G
		T, _ := pedersen.Commit(b, r, g, h)
		proof, err := commitRange.Prove(b, r, T, rs, g, h)
		if err != nil {
			t.Fatal(err)
		}
		verify, err := proof.Verify()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("res:", verify)
		witness, err = setComRangeProofWitness(proof, true)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println("constraints:", r1cs.GetNbConstraints())

		assert.SolvingSucceeded(r1cs, &witness)
	}
}
