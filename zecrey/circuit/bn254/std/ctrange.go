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
	"errors"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
	"log"
)

type CtRangeProofConstraints struct {
	// challenge
	C Variable
	// special commitment for each bit
	As [RangeMaxBits]Point
	Zs [RangeMaxBits]Variable
	// commitment for b
	A         Point
	H         Point
	IsEnabled Variable
}

// define for range proof test
func (circuit CtRangeProofConstraints) Define(api API) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tool := NewEccTool(api, params)
	VerifyCtRangeProof(tool, api, circuit, hFunc)
	return nil
}

func VerifyCtRangeProof(tool *EccTool, api API, proof CtRangeProofConstraints, hFunc MiMC) {
	A := Point{
		X: 0,
		Y: 1,
	}
	var current Point
	current.Neg(api, &proof.H)
	var A_As [RangeMaxBits]Point
	for i := 0; i < RangeMaxBits; i++ {
		var com, AihNegNeg Point
		AihNegNeg = tool.Add(proof.As[i], current)
		AihNegNeg.Neg(api, &AihNegNeg)
		AihNegNeg = tool.ScalarMul(AihNegNeg, proof.C)
		com = tool.ScalarBaseMul(proof.Zs[i])
		com = tool.Add(com, AihNegNeg)
		hFunc.Write(com.X, com.Y)
		ci := hFunc.Sum()
		A_As[i] = tool.ScalarMul(proof.As[i], ci)
		current.Double(api, &current, tool.params)
		hFunc.Reset()
	}
	for _, A_Ai := range A_As {
		hFunc.Write(A_Ai.X, A_Ai.Y)
	}
	hatc := hFunc.Sum()
	IsVariableEqual(api, proof.IsEnabled, hatc, proof.C)
	for _, Ai := range proof.As {
		A = tool.Add(A, Ai)
	}
	IsPointEqual(api, proof.IsEnabled, A, proof.A)
}

func SetEmptyCtRangeProofWitness() (witness CtRangeProofConstraints) {
	witness.H, _ = SetPointWitness(ZeroPoint)
	witness.A, _ = SetPointWitness(ZeroPoint)
	witness.C = ZeroInt
	// set buf and
	for i := 0; i < RangeMaxBits; i++ {
		witness.As[i], _ = SetPointWitness(ZeroPoint)
		witness.Zs[i] = ZeroInt
	}
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

/*
	setComRangeProofWitness set witness for the range proof
	@proof: original range proofs
*/
func SetCtRangeProofWitness(proof *ctrange.RangeProof, isEnabled bool) (witness CtRangeProofConstraints, err error) {
	if proof == nil {
		return witness, err
	}
	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetCtRangeProofWitness] invalid proof")
		return witness, errors.New("[SetCtRangeProofWitness] invalid proof")
	}
	//witness.G, err = SetPointWitness(proof.G)
	//if err != nil {
	//	return witness, err
	//}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.A, err = SetPointWitness(proof.A)
	if err != nil {
		return witness, err
	}
	witness.C = proof.C
	// set buf and
	for i := 0; i < RangeMaxBits; i++ {
		witness.As[i], err = SetPointWitness(proof.As[i])
		if err != nil {
			return witness, err
		}
		witness.Zs[i] = proof.Zs[i]
	}
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
