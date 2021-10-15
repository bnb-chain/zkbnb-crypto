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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

type CtRangeProofConstraints struct {
	// challenge
	C Variable
	// special commitment for each bit
	As [RangeMaxBits]Point
	Zs [RangeMaxBits]Variable
	// commitment for b
	A         Point
	G, H      Point
	IsEnabled Variable
}

// define for range proof test
func (circuit CtRangeProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// verify H
	H := Point{
		X: cs.Constant(HX),
		Y: cs.Constant(HY),
	}
	IsPointEqual(cs, circuit.IsEnabled, H, circuit.H)
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}
	verifyCtRangeProof(cs, circuit, params, hFunc)
	return nil
}

func verifyCtRangeProof(cs *ConstraintSystem, proof CtRangeProofConstraints, params twistededwards.EdCurve, hFunc MiMC) {
	A := Point{
		X: cs.Constant(0),
		Y: cs.Constant(1),
	}
	var current Point
	current.Neg(cs, &proof.H)
	var A_As [RangeMaxBits]Point
	for i := 0; i < RangeMaxBits; i++ {
		var com, AihNegNeg Point
		AihNegNeg.AddGeneric(cs, &proof.As[i], &current, params)
		AihNegNeg.Neg(cs, &AihNegNeg)
		AihNegNeg.ScalarMulNonFixedBase(cs, &AihNegNeg, proof.C, params)
		com.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Zs[i], params)
		com.AddGeneric(cs, &com, &AihNegNeg, params)
		hFunc.Write(com.X, com.Y)
		ci := hFunc.Sum()
		A_As[i].ScalarMulNonFixedBase(cs, &proof.As[i], ci, params)
		current.Double(cs, &current, params)
		hFunc.Reset()
	}
	for _, A_Ai := range A_As {
		hFunc.Write(A_Ai.X, A_Ai.Y)
	}
	hatc := hFunc.Sum()
	IsVariableEqual(cs, proof.IsEnabled, hatc, proof.C)
	for _, Ai := range proof.As {
		A.AddGeneric(cs, &A, &Ai, params)
	}
	IsPointEqual(cs, proof.IsEnabled, A, proof.A)
}

/*
	setComRangeProofWitness set witness for the range proof
	@proof: original range proofs
*/
func setCtRangeProofWitness(proof *ctrange.RangeProof, isEnabled bool) (witness CtRangeProofConstraints, err error) {
	if proof == nil {
		return witness, err
	}
	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		return witness, err
	}
	if !verifyRes {
		return witness, ErrInvalidProof
	}
	witness.G, err = SetPointWitness(proof.G)
	if err != nil {
		return witness, err
	}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.A, err = SetPointWitness(proof.A)
	if err != nil {
		return witness, err
	}
	witness.C.Assign(proof.C)
	// set buf and
	for i := 0; i < RangeMaxBits; i++ {
		witness.As[i], err = SetPointWitness(proof.As[i])
		if err != nil {
			return witness, err
		}
		witness.Zs[i].Assign(proof.Zs[i])
	}
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
