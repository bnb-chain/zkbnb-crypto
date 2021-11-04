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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type UnlockProofConstraints struct {
	// A
	A_pk Point
	// Z
	Z_sk Variable
	// common inputs
	Pk          Point
	ChainId     Variable
	AssetId     Variable
	Balance     Variable
	DeltaAmount Variable
	IsEnabled   Variable
}

// define for testing transfer proof
func (circuit UnlockProofConstraints) Define(curveID ecc.ID, api API) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, api)
	if err != nil {
		return err
	}
	VerifyUnlockProof(api, circuit, params, hFunc)
	return nil
}

func VerifyUnlockProof(
	api API,
	proof UnlockProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
) {
	hFunc.Write(FixedCurveParam(api))
	writePointIntoBuf(&hFunc, proof.Pk)
	writePointIntoBuf(&hFunc, proof.A_pk)
	hFunc.Write(proof.ChainId)
	hFunc.Write(proof.AssetId)
	hFunc.Write(proof.Balance)
	hFunc.Write(proof.DeltaAmount)
	c := hFunc.Sum()
	var l, r Point
	l.ScalarMulFixedBase(api, params.BaseX, params.BaseY, proof.Z_sk, params)
	r.ScalarMulNonFixedBase(api, &proof.Pk, c, params)
	r.AddGeneric(api, &r, &proof.A_pk, params)
	IsPointEqual(api, proof.IsEnabled, l, r)
}

func SetEmptyUnlockProofWitness() (witness UnlockProofConstraints) {
	witness.A_pk, _ = SetPointWitness(BasePoint)
	witness.Pk, _ = SetPointWitness(BasePoint)
	// response
	witness.Z_sk.Assign(ZeroInt)
	witness.ChainId.Assign(ZeroInt)
	witness.AssetId.Assign(ZeroInt)
	witness.Balance.Assign(ZeroInt)
	witness.DeltaAmount.Assign(ZeroInt)
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

// set the witness for RemoveLiquidity proof
func SetUnlockProofWitness(proof *zecrey.UnlockProof, isEnabled bool) (witness UnlockProofConstraints, err error) {
	if proof == nil {
		log.Println("[SetUnlockProofWitness] invalid params")
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetUnlockProofWitness] invalid proof:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetUnlockProofWitness] invalid proof")
		return witness, errors.New("[SetUnlockProofWitness] invalid proof")
	}

	witness.A_pk, err = SetPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.Pk, err = SetPointWitness(proof.Pk)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_sk.Assign(proof.Z_sk)
	witness.ChainId.Assign(uint64(proof.ChainId))
	witness.AssetId.Assign(uint64(proof.AssetId))
	witness.Balance.Assign(proof.Balance)
	witness.DeltaAmount.Assign(proof.DeltaAmount)
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
