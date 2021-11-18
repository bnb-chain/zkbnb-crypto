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

type RemoveLiquidityProofConstraints struct {
	// valid enc
	A_CLPL_Delta                Point
	A_CLPR_DeltaHExp_DeltaLPNeg Point
	Z_rDelta_LP                 Variable
	// ownership
	A_pk_u, A_T_uLPC_uLPRPrimeInv Point
	Z_sk_u, Z_bar_r_LP, Z_sk_uInv Variable
	// common inputs
	LC_pool_A, LC_pool_B           ElGamalEncConstraints
	C_uA_Delta, C_uB_Delta         ElGamalEncConstraints
	LC_poolA_Delta, LC_poolB_Delta ElGamalEncConstraints
	C_u_LP                         ElGamalEncConstraints
	C_u_LP_Delta                   ElGamalEncConstraints
	Pk_pool, Pk_u                  Point
	T_uLP                          Point
	R_poolA, R_poolB               Variable
	R_DeltaA, R_DeltaB             Variable
	B_pool_A, B_pool_B             Variable
	B_A_Delta, B_B_Delta           Variable
	MinB_A_Delta, MinB_B_Delta     Variable
	Delta_LP                       Variable
	P                              Variable
	AssetAId, AssetBId             Variable
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
func (circuit RemoveLiquidityProofConstraints) Define(curveID ecc.ID, api API) error {
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
	VerifyRemoveLiquidityProof(api, circuit, params, hFunc, H)

	return nil
}

func VerifyRemoveLiquidityProof(
	api API,
	proof RemoveLiquidityProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
	h Point,
) {
	tool := NewEccTool(api, params)
	hFunc.Write(FixedCurveParam(api))
	writePointIntoBuf(&hFunc, proof.Pk_u)
	writeEncIntoBuf(&hFunc, proof.C_u_LP)
	writeEncIntoBuf(&hFunc, proof.C_u_LP_Delta)
	writePointIntoBuf(&hFunc, proof.T_uLP)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
	writePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_pk_u)
	writePointIntoBuf(&hFunc, proof.A_T_uLPC_uLPRPrimeInv)
	// gas fee
	writePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)
	// compute challenge
	c := hFunc.Sum()
	// verify params
	verifyRemoveLiquidityParams(api, proof, tool, h)
	// verify enc
	var l1, r1 Point
	l1 = tool.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 = tool.Add(proof.A_CLPL_Delta, tool.ScalarMul(proof.C_u_LP_Delta.CL, c))
	IsPointEqual(api, proof.IsEnabled, l1, r1)
	// verify ownership
	var l2, r2 Point
	l2 = tool.ScalarBaseMul(proof.Z_sk_u)
	r2 = tool.Add(proof.A_pk_u, tool.ScalarMul(proof.Pk_u, c))
	IsPointEqual(api, proof.IsEnabled, l2, r2)
	C_uLPPrime := tool.EncAdd(proof.C_u_LP, proof.C_u_LP_Delta)
	C_uLPPrimeNeg := tool.NegElgamal(C_uLPPrime)
	l3 := tool.Add(
		tool.ScalarBaseMul(proof.Z_bar_r_LP),
		tool.ScalarMul(C_uLPPrimeNeg.CL, proof.Z_sk_uInv),
	)
	r3 := tool.Add(
		proof.A_T_uLPC_uLPRPrimeInv,
		tool.ScalarMul(
			tool.Add(
				proof.T_uLP,
				C_uLPPrimeNeg.CR,
			),
			c,
		),
	)
	IsPointEqual(api, proof.IsEnabled, l3, r3)
	// verify gas fee proof
	C_feeDelta := tool.ScalarMul(tool.Neg(h), proof.GasFee)
	C_feeLprimeInv := tool.Neg(proof.C_fee.CL)
	T_feeDivC_feeRprime := tool.Add(proof.T_fee, tool.Neg(tool.Add(proof.C_fee.CR, C_feeDelta)))
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l4 := tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_fee), tool.ScalarMul(C_feeLprimeInv, proof.Z_sk_uInv))
	r4 := tool.Add(proof.A_T_feeC_feeRPrimeInv, tool.ScalarMul(T_feeDivC_feeRprime, c))
	IsPointEqual(api, proof.IsEnabled, l4, r4)
}

func verifyRemoveLiquidityParams(
	api API,
	proof RemoveLiquidityProofConstraints,
	tool *EccTool,
	h Point,
) {

	C_uA_DeltaCL := tool.ScalarMul(proof.Pk_u, proof.R_DeltaA)
	C_uA_DeltaCRL := tool.ScalarBaseMul(proof.R_DeltaA)
	C_uA_DeltaCRR := tool.ScalarMul(h, proof.B_A_Delta)
	C_uA_Delta := ElGamalEncConstraints{
		CL: C_uA_DeltaCL,
		CR: tool.Add(C_uA_DeltaCRL, C_uA_DeltaCRR),
	}
	C_uB_DeltaCL := tool.ScalarMul(proof.Pk_u, proof.R_DeltaB)
	C_uB_DeltaCRL := tool.ScalarBaseMul(proof.R_DeltaB)
	C_uB_DeltaCRR := tool.ScalarMul(h, proof.B_B_Delta)
	C_uB_Delta := ElGamalEncConstraints{
		CL: C_uB_DeltaCL,
		CR: tool.Add(C_uB_DeltaCRL, C_uB_DeltaCRR),
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
	api.AssertIsLessOrEqual(LPCheck, Delta_LPCheck)
}

func SetEmptyRemoveLiquidityProofWitness() (witness RemoveLiquidityProofConstraints) {
	// valid enc
	witness.A_CLPL_Delta, _ = SetPointWitness(BasePoint)
	witness.A_CLPR_DeltaHExp_DeltaLPNeg, _ = SetPointWitness(BasePoint)
	witness.Z_rDelta_LP.Assign(ZeroInt)
	// ownership
	witness.A_pk_u, _ = SetPointWitness(BasePoint)
	witness.A_T_uLPC_uLPRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_sk_u.Assign(ZeroInt)
	witness.Z_bar_r_LP.Assign(ZeroInt)
	witness.Z_sk_uInv.Assign(ZeroInt)
	// common inputs
	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_u_LP, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_u_LP_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.Pk_pool, _ = SetPointWitness(BasePoint)
	witness.Pk_u, _ = SetPointWitness(BasePoint)
	witness.T_uLP, _ = SetPointWitness(BasePoint)
	witness.R_poolA.Assign(ZeroInt)
	witness.R_poolB.Assign(ZeroInt)
	witness.R_DeltaA.Assign(ZeroInt)
	witness.R_DeltaB.Assign(ZeroInt)
	witness.B_pool_A.Assign(ZeroInt)
	witness.B_pool_B.Assign(ZeroInt)
	witness.B_A_Delta.Assign(ZeroInt)
	witness.B_B_Delta.Assign(ZeroInt)
	witness.MinB_A_Delta.Assign(ZeroInt)
	witness.MinB_B_Delta.Assign(ZeroInt)
	witness.Delta_LP.Assign(ZeroInt)
	witness.P.Assign(ZeroInt)
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

// set the witness for RemoveLiquidity proof
func SetRemoveLiquidityProofWitness(proof *zecrey.RemoveLiquidityProof, isEnabled bool) (witness RemoveLiquidityProofConstraints, err error) {
	if proof == nil {
		log.Println("[SetRemoveLiquidityProofWitness] invalid params")
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetRemoveLiquidityProofWitness] invalid proof:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetRemoveLiquidityProofWitness] invalid proof")
		return witness, errors.New("[SetRemoveLiquidityProofWitness] invalid proof")
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
	witness.A_T_uLPC_uLPRPrimeInv, err = SetPointWitness(proof.A_T_uLPC_uLPRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_sk_u.Assign(proof.Z_sk_u)
	witness.Z_bar_r_LP.Assign(proof.Z_bar_r_LP)
	witness.Z_sk_uInv.Assign(proof.Z_sk_uInv)
	// common inputs
	witness.C_fee, err = SetElGamalEncWitness(proof.C_fee)
	if err != nil {
		return witness, err
	}
	witness.C_fee, err = SetElGamalEncWitness(proof.C_fee)
	if err != nil {
		return witness, err
	}
	witness.LC_pool_A, err = SetElGamalEncWitness(proof.LC_pool_A)
	if err != nil {
		return witness, err
	}
	witness.LC_pool_B, err = SetElGamalEncWitness(proof.LC_pool_B)
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
	witness.C_u_LP, err = SetElGamalEncWitness(proof.C_u_LP)
	if err != nil {
		return witness, err
	}
	witness.C_u_LP_Delta, err = SetElGamalEncWitness(proof.C_u_LP_Delta)
	if err != nil {
		return witness, err
	}
	witness.Pk_pool, err = SetPointWitness(proof.Pk_pool)
	if err != nil {
		return witness, err
	}
	witness.Pk_u, err = SetPointWitness(proof.Pk_u)
	if err != nil {
		return witness, err
	}
	witness.T_uLP, err = SetPointWitness(proof.T_uLP)
	if err != nil {
		return witness, err
	}
	witness.R_poolA.Assign(proof.R_poolA)
	witness.R_poolB.Assign(proof.R_poolB)
	witness.R_DeltaA.Assign(proof.R_DeltaA)
	witness.R_DeltaB.Assign(proof.R_DeltaB)
	witness.B_pool_A.Assign(proof.B_pool_A)
	witness.B_pool_B.Assign(proof.B_pool_B)
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.MinB_A_Delta.Assign(proof.MinB_A_Delta)
	witness.MinB_B_Delta.Assign(proof.MinB_B_Delta)
	witness.Delta_LP.Assign(proof.Delta_LP)
	witness.P.Assign(proof.P)
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
