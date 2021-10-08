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
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

func TestVerifyRangeProof(t *testing.T) {
	_, proof, err := ctrange.Prove(1, curve.G, curve.H)
	if err != nil {
		t.Fatal(err)
	}

	assert := groth16.NewAssert(t)
	var circuit, witness RangeProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	witness, err = setRangeProofWitness(proof, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.SolvingSucceeded(r1cs, &witness)
}
