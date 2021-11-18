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

type AddLiquidityProofConstraints struct {
	// valid enc
	A_CLPL_Delta                Point
	A_CLPR_DeltaHExp_DeltaLPNeg Point
	Z_rDelta_LP                 Variable
	// ownership
	A_pk_u, A_T_uAC_uARPrimeInv, A_T_uBC_uBRPrimeInv Point
	Z_sk_u, Z_bar_r_A, Z_bar_r_B, Z_sk_uInv          Variable
	// common inputs
	C_uA, C_uB                     ElGamalEncConstraints
	C_uA_Delta, C_uB_Delta         ElGamalEncConstraints
	LC_poolA_Delta, LC_poolB_Delta ElGamalEncConstraints
	C_LP_Delta                     ElGamalEncConstraints
	Pk_u, Pk_pool                  Point
	R_DeltaA, R_DeltaB             Variable
	T_uA, T_uB                     Point
	B_poolA, B_poolB               Variable
	B_A_Delta, B_B_Delta           Variable
	Delta_LP                       Variable
	// assets id
	AssetAId, AssetBId Variable
	// gas fee
	A_T_feeC_feeRPrimeInv Point
	Z_bar_r_fee           Variable
	C_fee                 ElGamalEncConstraints
	T_fee                 Point
	GasFeeAssetId         Variable
	GasFee                Variable
	IsEnabled             Variable
}

// define tests for verifying the swap proof
func (circuit AddLiquidityProofConstraints) Define(curveID ecc.ID, api API) error {
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
	tool := NewEccTool(api, params)
	VerifyAddLiquidityProof(tool, api, circuit, hFunc, H)

	return nil
}

func VerifyAddLiquidityProof(
	tool *EccTool,
	api API,
	proof AddLiquidityProofConstraints,
	hFunc MiMC,
	h Point,
) (c Variable, pkProofs [MaxRangeProofCount]CommonPkProof, tProofs [MaxRangeProofCount]CommonTProof) {
	hFunc.Write(FixedCurveParam(api))
	writePointIntoBuf(&hFunc, proof.Pk_u)
	writePointIntoBuf(&hFunc, proof.Pk_pool)
	writeEncIntoBuf(&hFunc, proof.C_uA)
	writeEncIntoBuf(&hFunc, proof.C_uB)
	writeEncIntoBuf(&hFunc, proof.C_uA_Delta)
	writeEncIntoBuf(&hFunc, proof.C_uB_Delta)
	writeEncIntoBuf(&hFunc, proof.C_LP_Delta)
	writePointIntoBuf(&hFunc, proof.T_uA)
	writePointIntoBuf(&hFunc, proof.T_uB)
	// assets id
	hFunc.Write(proof.AssetAId)
	hFunc.Write(proof.AssetBId)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
	writePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	// gas fee
	writePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)

	writePointIntoBuf(&hFunc, proof.A_pk_u)
	writePointIntoBuf(&hFunc, proof.A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&hFunc, proof.A_T_uBC_uBRPrimeInv)
	// compute challenge
	c = hFunc.Sum()
	// verify params
	verifyAddLiquidityParams(api, proof, tool, h)
	// verify enc
	l1 := tool.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 := tool.Add(proof.A_CLPL_Delta, tool.ScalarMul(proof.C_LP_Delta.CL, c))
	IsPointEqual(api, proof.IsEnabled, l1, r1)
	// verify ownership
	//l2 := tool.ScalarBaseMul(proof.Z_sk_u)
	//r2 := tool.Add(proof.A_pk_u, tool.ScalarMul(proof.Pk_u, c))
	//IsPointEqual(api, proof.IsEnabled, l2, r2)
	// check if gas fee asset id is the same as asset a
	assetADiff := api.Sub(proof.GasFeeAssetId, proof.AssetAId)
	assetBDiff := api.Sub(proof.GasFeeAssetId, proof.AssetBId)
	isSameAssetA := api.IsZero(assetADiff)
	isSameAssetB := api.IsZero(assetBDiff)
	hNeg := tool.Neg(h)
	// if same, check params
	IsElGamalEncEqual(api, isSameAssetA, proof.C_uA, proof.C_fee)
	IsPointEqual(api, isSameAssetA, proof.A_T_uAC_uARPrimeInv, proof.A_T_feeC_feeRPrimeInv)
	deltaFee := tool.ScalarMul(hNeg, proof.GasFee)
	deltaA := SelectPoint(api, isSameAssetA, deltaFee, zeroPoint(api))
	deltaB := SelectPoint(api, isSameAssetB, deltaFee, zeroPoint(api))
	C_uAPrime := tool.EncAdd(proof.C_uA, proof.C_uA_Delta)
	C_uAPrime.CR = tool.Add(C_uAPrime.CR, deltaA)
	C_uAPrimeNeg := tool.NegElgamal(C_uAPrime)
	//l3 := tool.Add(
	//	tool.ScalarBaseMul(proof.Z_bar_r_A),
	//	tool.ScalarMul(C_uAPrimeNeg.CL, proof.Z_sk_uInv),
	//)
	//r3 := tool.Add(
	//	proof.A_T_uAC_uARPrimeInv,
	//	tool.ScalarMul(
	//		tool.Add(
	//			proof.T_uA,
	//			C_uAPrimeNeg.CR,
	//		),
	//		c,
	//	),
	//)
	//IsPointEqual(api, proof.IsEnabled, l3, r3)
	C_uBPrime := tool.EncAdd(proof.C_uB, proof.C_uB_Delta)
	C_uBPrime.CR = tool.Add(C_uBPrime.CR, deltaB)
	C_uBPrimeNeg := tool.NegElgamal(C_uBPrime)
	//l4 := tool.Add(
	//	tool.ScalarBaseMul(proof.Z_bar_r_B),
	//	tool.ScalarMul(C_uBPrimeNeg.CL, proof.Z_sk_uInv),
	//)
	//r4 := tool.Add(
	//	proof.A_T_uBC_uBRPrimeInv,
	//	tool.ScalarMul(
	//		tool.Add(
	//			proof.T_uB,
	//			C_uBPrimeNeg.CR,
	//		),
	//		c,
	//	),
	//)
	//IsPointEqual(api, proof.IsEnabled, l4, r4)
	// fee
	C_feeRPrime := tool.Add(proof.C_fee.CR, deltaFee)
	C_feePrime := ElGamalEncConstraints{CL: proof.C_fee.CL, CR: C_feeRPrime}
	C_feePrimeNeg := tool.NegElgamal(C_feePrime)
	C_feePrimeNeg = SelectElgamal(api, isSameAssetA, C_uAPrimeNeg, C_feePrimeNeg)
	C_feePrimeNeg = SelectElgamal(api, isSameAssetB, C_uBPrimeNeg, C_feePrimeNeg)
	//l5 := tool.Add(
	//	tool.ScalarBaseMul(proof.Z_bar_r_fee),
	//	tool.ScalarMul(C_feePrimeNeg.CL, proof.Z_sk_uInv),
	//)
	//r5 := tool.Add(
	//	proof.A_T_feeC_feeRPrimeInv,
	//	tool.ScalarMul(
	//		tool.Add(
	//			proof.T_fee,
	//			C_feePrimeNeg.CR,
	//		),
	//		c,
	//	),
	//)
	//IsPointEqual(api, proof.IsEnabled, l5, r5)
	// set common parts
	pkProofs[0] = SetPkProof(proof.Pk_u, proof.A_pk_u, proof.Z_sk_u, proof.Z_sk_uInv)
	for i := 1; i < MaxRangeProofCount; i++ {
		pkProofs[i] = pkProofs[0]
	}
	tProofs[0] = SetTProof(C_uAPrimeNeg, proof.A_T_uAC_uARPrimeInv, proof.Z_bar_r_A, proof.T_uA)
	tProofs[1] = SetTProof(C_uBPrimeNeg, proof.A_T_uBC_uBRPrimeInv, proof.Z_bar_r_B, proof.T_uB)
	tProofs[2] = SetTProof(C_feePrimeNeg, proof.A_T_feeC_feeRPrimeInv, proof.Z_bar_r_fee, proof.T_fee)
	for i := 2; i < MaxRangeProofCount; i++ {
		tProofs[i] = tProofs[0]
	}
	return c, pkProofs, tProofs
}

func verifyAddLiquidityParams(
	api API,
	proof AddLiquidityProofConstraints,
	tool *EccTool,
	h Point,
) {
	// C_uA_Delta
	hNeg := tool.Neg(h)
	C_uA_DeltaCL := tool.ScalarMul(proof.Pk_u, proof.R_DeltaA)
	C_uA_DeltaCRL := tool.ScalarBaseMul(proof.R_DeltaA)
	C_uA_DeltaCRR := tool.ScalarMul(hNeg, proof.B_A_Delta)
	C_uA_DeltaCR := tool.Add(C_uA_DeltaCRL, C_uA_DeltaCRR)
	C_uA_Delta := ElGamalEncConstraints{
		CL: C_uA_DeltaCL,
		CR: C_uA_DeltaCR,
	}
	// C_uB_Delta
	C_uB_DeltaCL := tool.ScalarMul(proof.Pk_u, proof.R_DeltaB)
	C_uB_DeltaCRL := tool.ScalarBaseMul(proof.R_DeltaB)
	C_uB_DeltaCRR := tool.ScalarMul(hNeg, proof.B_B_Delta)
	C_uB_DeltaCR := tool.Add(C_uB_DeltaCRL, C_uB_DeltaCRR)
	C_uB_Delta := ElGamalEncConstraints{
		CL: C_uB_DeltaCL,
		CR: C_uB_DeltaCR,
	}
	LC_poolA_Delta := ElGamalEncConstraints{
		CL: tool.ScalarMul(proof.Pk_pool, proof.R_DeltaA),
		CR: tool.Add(C_uA_DeltaCRL, tool.Neg(C_uA_DeltaCRR)),
	}
	LC_poolB_Delta := ElGamalEncConstraints{
		CL: tool.ScalarMul(proof.Pk_pool, proof.R_DeltaB),
		CR: tool.Add(C_uB_DeltaCRL, tool.Neg(C_uB_DeltaCRR)),
	}
	IsElGamalEncEqual(api, proof.IsEnabled, C_uA_Delta, proof.C_uA_Delta)
	IsElGamalEncEqual(api, proof.IsEnabled, C_uB_Delta, proof.C_uB_Delta)
	IsElGamalEncEqual(api, proof.IsEnabled, LC_poolA_Delta, proof.LC_poolA_Delta)
	IsElGamalEncEqual(api, proof.IsEnabled, LC_poolB_Delta, proof.LC_poolB_Delta)
	// verify LP
	Delta_LPCheck := api.Mul(proof.B_A_Delta, proof.B_B_Delta)
	LPCheck := api.Mul(proof.Delta_LP, proof.Delta_LP)
	api.AssertIsLessOrEqual(Delta_LPCheck, LPCheck)
	// verify AMM info & DAO balance info
	l := api.Mul(proof.B_poolB, proof.B_A_Delta)
	r := api.Mul(proof.B_poolA, proof.B_B_Delta)
	api.AssertIsEqual(l, r)
}

func SetEmptyAddLiquidityProofWitness() (witness AddLiquidityProofConstraints) {
	// valid enc
	witness.A_CLPL_Delta, _ = SetPointWitness(BasePoint)
	witness.A_CLPR_DeltaHExp_DeltaLPNeg, _ = SetPointWitness(BasePoint)
	witness.Z_rDelta_LP.Assign(ZeroInt)
	// ownership
	witness.A_pk_u, _ = SetPointWitness(BasePoint)
	witness.A_T_uAC_uARPrimeInv, _ = SetPointWitness(BasePoint)
	witness.A_T_uBC_uBRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_sk_u.Assign(ZeroInt)
	witness.Z_bar_r_A.Assign(ZeroInt)
	witness.Z_bar_r_B.Assign(ZeroInt)
	witness.Z_sk_uInv.Assign(ZeroInt)
	// common inputs
	witness.C_uA, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uB, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_LP_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.Pk_u, _ = SetPointWitness(BasePoint)
	witness.Pk_pool, _ = SetPointWitness(BasePoint)
	witness.R_DeltaA.Assign(ZeroInt)
	witness.R_DeltaB.Assign(ZeroInt)
	witness.T_uA, _ = SetPointWitness(BasePoint)
	witness.T_uB, _ = SetPointWitness(BasePoint)
	witness.B_poolA.Assign(ZeroInt)
	witness.B_poolB.Assign(ZeroInt)
	witness.B_A_Delta.Assign(ZeroInt)
	witness.B_B_Delta.Assign(ZeroInt)
	witness.Delta_LP.Assign(ZeroInt)
	// assets id
	witness.AssetAId.Assign(ZeroInt)
	witness.AssetBId.Assign(ZeroInt)
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

// set the witness for swap proof
func SetAddLiquidityProofWitness(proof *zecrey.AddLiquidityProof, isEnabled bool) (witness AddLiquidityProofConstraints, err error) {
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

	// valid enc
	witness.A_CLPL_Delta, err = SetPointWitness(proof.A_CLPL_Delta)
	if err != nil {
		return witness, err
	}
	witness.A_CLPR_DeltaHExp_DeltaLPNeg, err = SetPointWitness(proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	if err != nil {
		return witness, err
	}
	witness.Z_rDelta_LP.Assign(proof.Z_rDelta_LP)
	// ownership
	witness.A_pk_u, err = SetPointWitness(proof.A_pk_u)
	if err != nil {
		return witness, err
	}
	witness.A_T_uAC_uARPrimeInv, err = SetPointWitness(proof.A_T_uAC_uARPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.A_T_uBC_uBRPrimeInv, err = SetPointWitness(proof.A_T_uBC_uBRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_sk_u.Assign(proof.Z_sk_u)
	witness.Z_bar_r_A.Assign(proof.Z_bar_r_A)
	witness.Z_bar_r_B.Assign(proof.Z_bar_r_B)
	witness.Z_sk_uInv.Assign(proof.Z_sk_uInv)
	// common inputs
	witness.C_uA, err = SetElGamalEncWitness(proof.C_uA)
	if err != nil {
		return witness, err
	}
	witness.C_uB, err = SetElGamalEncWitness(proof.C_uB)
	if err != nil {
		return witness, err
	}
	witness.C_uA_Delta, err = SetElGamalEncWitness(proof.C_uA_Delta)
	if err != nil {
		return witness, err
	}
	witness.C_uB_Delta, err = SetElGamalEncWitness(proof.C_uB_Delta)
	if err != nil {
		return witness, err
	}
	witness.LC_poolA_Delta, err = SetElGamalEncWitness(proof.LC_poolA_Delta)
	if err != nil {
		return witness, err
	}
	witness.LC_poolB_Delta, err = SetElGamalEncWitness(proof.LC_poolB_Delta)
	if err != nil {
		return witness, err
	}
	witness.C_LP_Delta, err = SetElGamalEncWitness(proof.C_LP_Delta)
	if err != nil {
		return witness, err
	}
	witness.Pk_u, err = SetPointWitness(proof.Pk_u)
	if err != nil {
		return witness, err
	}
	witness.Pk_pool, err = SetPointWitness(proof.Pk_pool)
	if err != nil {
		return witness, err
	}
	witness.R_DeltaA.Assign(proof.R_DeltaA)
	witness.R_DeltaB.Assign(proof.R_DeltaB)
	witness.T_uA, err = SetPointWitness(proof.T_uA)
	if err != nil {
		return witness, err
	}
	witness.T_uB, err = SetPointWitness(proof.T_uB)
	if err != nil {
		return witness, err
	}
	witness.B_poolA.Assign(proof.B_poolA)
	witness.B_poolB.Assign(proof.B_poolB)
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.Delta_LP.Assign(proof.Delta_LP)
	// assets id
	witness.AssetAId.Assign(uint64(proof.AssetAId))
	witness.AssetBId.Assign(uint64(proof.AssetBId))
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
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
