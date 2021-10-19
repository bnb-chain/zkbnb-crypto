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

// WithdrawProof in circuit
type WithdrawProofConstraints struct {
	// commitments
	A_pk, A_TDivCRprime Point
	// response
	Z_rbar, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	//BPrimeRangeProof CtRangeProofConstraints
	// common inputs
	BStar       Variable
	Fee         Variable
	CRStar      Point
	C           ElGamalEncConstraints
	T, Pk       Point
	ReceiveAddr Variable
	IsEnabled   Variable
}

// define tests for verifying the withdraw proof
func (circuit WithdrawProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
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
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}
	VerifyWithdrawProof(cs, circuit, params, hFunc, H)
	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@cs: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifyWithdrawProof(
	cs *ConstraintSystem,
	proof WithdrawProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
	h Point,
) {
	//IsPointEqual(cs, proof.IsEnabled, proof.BPrimeRangeProof.A, proof.T)
	// verify if the CRStar is correct
	var hNeg, CRCheck Point
	delta := cs.Add(proof.BStar, proof.Fee)
	hNeg.Neg(cs, &h)
	CRCheck.ScalarMulNonFixedBase(cs, &hNeg, delta, params)
	IsPointEqual(cs, proof.IsEnabled, CRCheck, proof.CRStar)
	// Verify range proof first
	// mimc
	//rangeFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	//if err != nil {
	//	log.Println("[VerifyWithdrawProof] invalid range hash func")
	//	return
	//}
	//VerifyCtRangeProof(cs, proof.BPrimeRangeProof, params, rangeFunc)
	// generate the challenge
	var (
		c                       Variable
		CLprimeInv, TDivCRprime Point
	)
	CLprimeInv.Neg(cs, &proof.C.CL)
	TDivCRprime.AddGeneric(cs, &proof.C.CR, &proof.CRStar, params)
	TDivCRprime.Neg(cs, &TDivCRprime)
	TDivCRprime.AddGeneric(cs, &TDivCRprime, &proof.T, params)
	hFunc.Write(FixedCurveParam(cs))
	hFunc.Write(proof.ReceiveAddr)
	writeEncIntoBuf(&hFunc, proof.C)
	writePointIntoBuf(&hFunc, proof.CRStar)
	writePointIntoBuf(&hFunc, proof.T)
	writePointIntoBuf(&hFunc, proof.Pk)
	writePointIntoBuf(&hFunc, proof.A_pk)
	writePointIntoBuf(&hFunc, proof.A_TDivCRprime)
	c = hFunc.Sum()
	// Verify balance
	verifyBalance(
		cs,
		proof.Pk, proof.A_pk, CLprimeInv, TDivCRprime, proof.A_TDivCRprime,
		c,
		proof.Z_sk, proof.Z_skInv, proof.Z_rbar,
		proof.IsEnabled,
		params,
	)
}

/*
	verifyBalance verify the remaining balance is positive
	@cs: the constraint system
	@pk,CLprimeInv,TDivCRprime: public inputs
	@A_pk,A_TDivCRprime: the random commitment
	@z_sk, z_skInv, z_rbar: the response value
	@params: params for the curve tebn254
*/
func verifyBalance(
	cs *ConstraintSystem,
	pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime Point,
	c Variable,
	z_sk, z_skInv, z_rbar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify pk = g^{sk}
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_sk, params)
	r1.ScalarMulNonFixedBase(cs, &pk, c, params)
	r1.AddGeneric(cs, &A_pk, &r1, params)
	IsPointEqual(cs, isEnabled, l1, r1)

	var g_zrbar, l2, r2 Point
	// verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	g_zrbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rbar, params)
	l2.ScalarMulNonFixedBase(cs, &CLprimeInv, z_skInv, params)
	l2.AddGeneric(cs, &g_zrbar, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &TDivCRprime, c, params)
	r2.AddGeneric(cs, &A_TDivCRprime, &r2, params)
	IsPointEqual(cs, isEnabled, l2, r2)
}

func SetEmptyWithdrawProofWitness() (witness WithdrawProofConstraints) {

	witness.A_pk, _ = SetPointWitness(BasePoint)

	witness.A_TDivCRprime, _ = SetPointWitness(BasePoint)


	// response
	witness.Z_rbar.Assign(ZeroInt)
	witness.Z_sk.Assign(ZeroInt)
	witness.Z_skInv.Assign(ZeroInt)
	//witness.BPrimeRangeProof, _ = SetCtRangeProofWitness(BPrimeRangeProof, isEnabled)
	//if err != nil {
	//	return witness, _
	//}
	// common inputs
	witness.C, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.CRStar, _ = SetPointWitness(BasePoint)

	witness.T, _ = SetPointWitness(BasePoint)

	witness.Pk, _ = SetPointWitness(BasePoint)

	witness.ReceiveAddr.Assign(ZeroInt)
	witness.BStar.Assign(ZeroInt)
	witness.Fee.Assign(ZeroInt)
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

// set the witness for withdraw proof
func SetWithdrawProofWitness(proof *zecrey.WithdrawProof, isEnabled bool) (witness WithdrawProofConstraints, err error) {
	if proof == nil {
		log.Println("[SetWithdrawProofWitness] invalid params")
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetWithdrawProofWitness] invalid proof:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetWithdrawProofWitness] invalid proof")
		return witness, errors.New("[SetWithdrawProofWitness] invalid proof")
	}

	witness.A_pk, err = SetPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.A_TDivCRprime, err = SetPointWitness(proof.A_TDivCRprime)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_rbar.Assign(proof.Z_rbar)
	witness.Z_sk.Assign(proof.Z_sk)
	witness.Z_skInv.Assign(proof.Z_skInv)
	//witness.BPrimeRangeProof, err = SetCtRangeProofWitness(proof.BPrimeRangeProof, isEnabled)
	//if err != nil {
	//	return witness, err
	//}
	// common inputs
	witness.C, err = SetElGamalEncWitness(proof.C)
	if err != nil {
		return witness, err
	}
	witness.CRStar, err = SetPointWitness(proof.CRStar)
	if err != nil {
		return witness, err
	}
	witness.T, err = SetPointWitness(proof.T)
	if err != nil {
		return witness, err
	}
	witness.Pk, err = SetPointWitness(proof.Pk)
	if err != nil {
		return witness, err
	}
	witness.ReceiveAddr.Assign(proof.ReceiveAddr)
	witness.BStar.Assign(proof.BStar)
	witness.Fee.Assign(proof.Fee)
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
