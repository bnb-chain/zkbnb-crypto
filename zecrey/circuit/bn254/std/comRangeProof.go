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
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type ComRangeProofConstraints struct {
	// bit proof
	Cas, Cbs [RangeMaxBits]Point
	Zas, Zbs [RangeMaxBits]Variable
	// public statements
	T                    Point
	G                    Point
	As                   [RangeMaxBits]Point
	C1, C2               Variable
	C                    Variable
	A_A                  Point
	Z_alpha_r, Z_alpha_b Variable
	IsEnabled            Variable
}

// define for range proof test
func (circuit *ComRangeProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	verifyComRangeProof(cs, *circuit, params)
	return nil
}

/*
	verifyComRangeProof verify the range proof
	@cs: the constraint system
	@proof: the CommitmentRangeProof
	@params: params for the curve tebn254
*/
func verifyComRangeProof(
	cs *ConstraintSystem,
	proof ComRangeProofConstraints,
	params twistededwards.EdCurve,
) {
	TCheck := Point{
		X: cs.Constant(0),
		Y: cs.Constant(1),
	}
	for _, Ai := range proof.As {
		TCheck.AddGeneric(cs, &TCheck, &Ai, params)
	}
	// check commitment first
	IsPointEqual(cs, proof.IsEnabled, TCheck, proof.T)
	// check h^{z_{\alpha_{r}}} g^{z_{\alpha_{b}}} = A_A A^c
	var l1, hzb, r1 Point
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_alpha_r, params)
	l1.AddGeneric(cs, &l1, hzb.ScalarMulNonFixedBase(cs, &proof.G, proof.Z_alpha_b, params), params)
	r1.ScalarMulNonFixedBase(cs, &proof.T, proof.C, params)
	r1.AddGeneric(cs, &r1, &proof.A_A, params)
	IsPointEqual(cs, proof.IsEnabled, l1, r1)
	// check A_i
	base := Neg(cs, proof.G, params)
	var A2 Point
	for i, A1 := range proof.As {
		A2.AddGeneric(cs, &A1, base, params)
		verifyBitProof(cs, proof.Zas[i], proof.Zbs[i], proof.Cas[i], proof.Cbs[i], A1, A2, proof.C1, proof.C2, proof.IsEnabled, params)
		base.AddGeneric(cs, base, base, params)
	}
}

func verifyBitProof(
	cs *ConstraintSystem,
	za, zb Variable,
	Ca, Cb Point,
	A1, A2 Point,
	c1, c2 Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// check h^{za} == Ca A1^c1
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, za, params)
	r1.ScalarMulNonFixedBase(cs, &A1, c1, params)
	r1.AddGeneric(cs, &Ca, &r1, params)
	IsPointEqual(cs, isEnabled, l1, r1)
	var l2, r2 Point
	// check h^{zb} == Cb A2^c2
	l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zb, params)
	r2.ScalarMulNonFixedBase(cs, &A2, c2, params)
	r2.AddGeneric(cs, &Cb, &r2, params)
	IsPointEqual(cs, isEnabled, l2, r2)
}

/*
	setComRangeProofWitness set witness for the range proof
	@proof: original range proofs
*/
func setComRangeProofWitness(proof *commitRange.ComRangeProof, isEnabled bool) (witness ComRangeProofConstraints, err error) {
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
	witness.T, err = SetPointWitness(proof.T)
	// compute c
	// set buf and
	for i, Ai := range proof.As {
		witness.As[i], err = SetPointWitness(Ai)
		if err != nil {
			return witness, err
		}
		witness.Cas[i], err = SetPointWitness(proof.Cas[i])
		if err != nil {
			return witness, err
		}
		witness.Cbs[i], err = SetPointWitness(proof.Cbs[i])
		if err != nil {
			return witness, err
		}
		witness.Zas[i].Assign(proof.Zas[i].String())
		witness.Zbs[i].Assign(proof.Zbs[i].String())
	}
	witness.C1.Assign(proof.C1)
	witness.C2.Assign(proof.C2)
	witness.A_A, err = SetPointWitness(proof.A_A)
	if err != nil {
		return witness, err
	}
	witness.Z_alpha_r.Assign(proof.Z_alpha_r)
	witness.Z_alpha_b.Assign(proof.Z_alpha_b)
	witness.C.Assign(ffmath.Xor(proof.C1, proof.C2))
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
