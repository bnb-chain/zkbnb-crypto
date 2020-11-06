// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark/internal/generators DO NOT EDIT

package groth16

import (
	"bytes"
	"math/big"
	"reflect"

	curve "github.com/consensys/gurvy/bw761"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"

	"testing"
)

func TestProofSerialization(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000

	properties := gopter.NewProperties(parameters)

	properties.Property("Proof -> writer -> reader -> Proof should stay constant", prop.ForAll(
		func(ar, krs curve.G1Affine, bs curve.G2Affine) bool {
			var proof, pCompressed, pRaw Proof

			// create a random proof
			proof.Ar = ar
			proof.Krs = krs
			proof.Bs = bs

			var bufCompressed bytes.Buffer
			written, err := proof.WriteTo(&bufCompressed)
			if err != nil {
				return false
			}

			read, err := pCompressed.ReadFrom(&bufCompressed)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			var bufRaw bytes.Buffer
			written, err = proof.WriteTo(&bufRaw)
			if err != nil {
				return false
			}

			read, err = pRaw.ReadFrom(&bufRaw)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			return reflect.DeepEqual(&proof, &pCompressed) && reflect.DeepEqual(&proof, &pRaw)
		},
		GenG1(),
		GenG1(),
		GenG2(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

func GenG1() gopter.Gen {
	_, _, g1GenAff, _ := curve.Generators()
	return func(genParams *gopter.GenParameters) *gopter.GenResult {
		var scalar big.Int
		scalar.SetUint64(genParams.NextUint64())

		var g1 curve.G1Affine
		g1.ScalarMultiplication(&g1GenAff, &scalar)

		genResult := gopter.NewGenResult(g1, gopter.NoShrinker)
		return genResult
	}
}

func GenG2() gopter.Gen {
	_, _, _, g2GenAff := curve.Generators()
	return func(genParams *gopter.GenParameters) *gopter.GenResult {
		var scalar big.Int
		scalar.SetUint64(genParams.NextUint64())

		var g2 curve.G2Affine
		g2.ScalarMultiplication(&g2GenAff, &scalar)

		genResult := gopter.NewGenResult(g2, gopter.NoShrinker)
		return genResult
	}
}
