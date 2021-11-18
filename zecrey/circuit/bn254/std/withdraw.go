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
	Z_bar_r, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	//BPrimeRangeProof      CtRangeProofConstraints
	//GasFeePrimeRangeProof CtRangeProofConstraints
	// common inputs
	BStar       Variable
	C           ElGamalEncConstraints
	T, Pk       Point
	ReceiveAddr Variable
	AssetId     Variable
	// gas fee
	A_T_feeC_feeRPrimeInv Point
	Z_bar_r_fee           Variable
	C_fee                 ElGamalEncConstraints
	T_fee                 Point
	GasFeeAssetId         Variable
	GasFee                Variable
	IsEnabled             Variable
}

// define tests for verifying the withdraw proof
func (circuit WithdrawProofConstraints) Define(curveID ecc.ID, api API) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// verify H
	H := Point{
		X: api.Constant(HX),
		Y: api.Constant(HY),
	}
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, api)
	if err != nil {
		return err
	}
	VerifyWithdrawProof(api, circuit, params, hFunc, H)
	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@api: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifyWithdrawProof(
	api API,
	proof WithdrawProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
	h Point,
) {
	tool := NewEccTool(api, params)
	// check params
	assetIdDiff := api.Sub(proof.GasFeeAssetId, proof.AssetId)
	isSameAsset := api.IsZero(assetIdDiff)
	IsElGamalEncEqual(api, isSameAsset, proof.C, proof.C_fee)
	IsPointEqual(api, isSameAsset, proof.A_TDivCRprime, proof.A_T_feeC_feeRPrimeInv)
	deltaFee := api.Select(isSameAsset, proof.GasFee, api.Constant(0))
	var (
		c                                      Variable
		hNeg, CRDelta, CLprimeInv, TDivCRprime Point
		C_feeLprimeInv                         Point
		T_feeDivC_feeRprime                    Point
		C_feePrimeInv                          Point
	)
	hNeg.Neg(api, &h)
	deltaBalance := api.Add(proof.BStar, deltaFee)
	CRDelta = tool.ScalarMul(hNeg, deltaBalance)
	CLprimeInv.Neg(api, &proof.C.CL)
	CRPrime := tool.Add(proof.C.CR, CRDelta)
	TDivCRprime.Neg(api, &CRPrime)
	TDivCRprime = tool.Add(proof.T, TDivCRprime)
	C_feeDelta := tool.ScalarMul(hNeg, proof.GasFee)
	C_feeLprimeInv.Neg(api, &proof.C_fee.CL)
	C_feePrimeInv = tool.Add(proof.C_fee.CR, C_feeDelta)
	C_feePrimeInv.Neg(api, &C_feePrimeInv)
	T_feeDivC_feeRprime = tool.Add(proof.T_fee, C_feePrimeInv)
	C_feeLprimeInv = SelectPoint(api, isSameAsset, CLprimeInv, C_feeLprimeInv)
	T_feeDivC_feeRprime = SelectPoint(api, isSameAsset, TDivCRprime, T_feeDivC_feeRprime)
	hFunc.Write(FixedCurveParam(api))
	hFunc.Write(proof.ReceiveAddr)
	writeEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)
	hFunc.Write(proof.AssetId)
	// gas fee
	writeEncIntoBuf(&hFunc, proof.C)
	writePointIntoBuf(&hFunc, proof.T)
	writePointIntoBuf(&hFunc, proof.T_fee)
	writePointIntoBuf(&hFunc, proof.Pk)
	writePointIntoBuf(&hFunc, proof.A_pk)
	writePointIntoBuf(&hFunc, proof.A_TDivCRprime)
	writePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	c = hFunc.Sum()
	// Verify balance
	verifyBalance(
		api,
		proof.Pk, proof.A_pk,
		CLprimeInv, TDivCRprime, proof.A_TDivCRprime,
		c,
		proof.Z_sk, proof.Z_skInv, proof.Z_bar_r,
		proof.IsEnabled, params)
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l1 := tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_fee), tool.ScalarMul(C_feeLprimeInv, proof.Z_skInv))
	r1 := tool.Add(proof.A_T_feeC_feeRPrimeInv, tool.ScalarMul(T_feeDivC_feeRprime, c))
	IsPointEqual(api, proof.IsEnabled, l1, r1)
}

/*
	verifyBalance verify the remaining balance is positive
	@api: the constraint system
	@pk,CLprimeInv,TDivCRprime: public inputs
	@A_pk,A_TDivCRprime: the random commitment
	@z_sk, z_skInv, z_rbar: the response value
	@params: params for the curve tebn254
*/
func verifyBalance(
	api API,
	pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime Point,
	c Variable,
	z_sk, z_skInv, z_rbar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify pk = g^{sk}
	l1.ScalarMulFixedBase(api, params.BaseX, params.BaseY, z_sk, params)
	r1.ScalarMulNonFixedBase(api, &pk, c, params)
	r1.AddGeneric(api, &A_pk, &r1, params)
	IsPointEqual(api, isEnabled, l1, r1)

	var g_zrbar, l2, r2 Point
	// verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	g_zrbar.ScalarMulFixedBase(api, params.BaseX, params.BaseY, z_rbar, params)
	l2.ScalarMulNonFixedBase(api, &CLprimeInv, z_skInv, params)
	l2.AddGeneric(api, &g_zrbar, &l2, params)
	r2.ScalarMulNonFixedBase(api, &TDivCRprime, c, params)
	r2.AddGeneric(api, &A_TDivCRprime, &r2, params)
	IsPointEqual(api, isEnabled, l2, r2)
}

func SetEmptyWithdrawProofWitness() (witness WithdrawProofConstraints) {

	// commitments
	witness.A_pk, _ = SetPointWitness(BasePoint)
	witness.A_TDivCRprime, _ = SetPointWitness(BasePoint)
	// response
	witness.Z_bar_r.Assign(ZeroInt)
	witness.Z_sk.Assign(ZeroInt)
	witness.Z_skInv.Assign(ZeroInt)
	// common inputs
	witness.BStar.Assign(ZeroInt)
	witness.C, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.T, _ = SetPointWitness(BasePoint)
	witness.Pk, _ = SetPointWitness(BasePoint)
	witness.ReceiveAddr.Assign(ZeroInt)
	witness.AssetId.Assign(ZeroInt)
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_bar_r_fee.Assign(ZeroInt)
	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.T_fee, _ = SetPointWitness(BasePoint)
	witness.GasFeeAssetId.Assign(ZeroInt)
	witness.GasFee.Assign(ZeroInt)
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
	// commitments
	witness.A_pk, err = SetPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.A_TDivCRprime, err = SetPointWitness(proof.A_TDivCRprime)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_bar_r.Assign(proof.Z_bar_r)
	witness.Z_sk.Assign(proof.Z_sk)
	witness.Z_skInv.Assign(proof.Z_skInv)
	// common inputs
	witness.BStar.Assign(proof.BStar)
	witness.C, err = SetElGamalEncWitness(proof.C)
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
	witness.AssetId.Assign(uint64(proof.AssetId))
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, err = SetPointWitness(proof.A_T_feeC_feeRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_bar_r_fee.Assign(proof.Z_bar_r_fee)
	witness.C_fee, err = SetElGamalEncWitness(proof.C_fee)
	if err != nil {
		return witness, err
	}
	witness.T_fee, err = SetPointWitness(proof.T_fee)
	if err != nil {
		return witness, err
	}
	witness.GasFeeAssetId.Assign(uint64(proof.GasFeeAssetId))
	witness.GasFee.Assign(proof.GasFee)
	//witness.BPrimeRangeProof, err = SetCtRangeProofWitness(proof.BPrimeRangeProof, isEnabled)
	//if err != nil {
	//	return witness, err
	//}
	// common inputs
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
