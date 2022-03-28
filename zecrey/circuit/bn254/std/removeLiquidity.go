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
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
	"math/big"
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
	C_fee_DeltaForFrom    ElGamalEncConstraints
	C_fee_DeltaForGas     ElGamalEncConstraints
	T_fee                 Point
	GasFeeAssetId         Variable
	GasFee                Variable
	IsEnabled             Variable
}

// define tests for verifying the swap proof
func (circuit RemoveLiquidityProofConstraints) Define(api API) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	// verify H
	H := Point{
		X: HX,
		Y: HY,
	}
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tool := NewEccTool(api, params)
	VerifyRemoveLiquidityProof(tool, api, &circuit, hFunc, H)

	return nil
}

func VerifyRemoveLiquidityProof(
	tool *EccTool,
	api API,
	proof *RemoveLiquidityProofConstraints,
	hFunc MiMC,
	h Point,
) (c Variable, pkProofs [MaxRangeProofCount]CommonPkProof, tProofs [MaxRangeProofCount]CommonTProof) {
	hFunc.Write(FixedCurveParam(api))
	WritePointIntoBuf(&hFunc, proof.Pk_u)
	WriteEncIntoBuf(&hFunc, proof.C_u_LP)
	WriteEncIntoBuf(&hFunc, proof.C_u_LP_Delta)
	WritePointIntoBuf(&hFunc, proof.T_uLP)
	// write into buf
	WritePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
	WritePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	WritePointIntoBuf(&hFunc, proof.A_pk_u)
	WritePointIntoBuf(&hFunc, proof.A_T_uLPC_uLPRPrimeInv)
	// gas fee
	WritePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	WriteEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)
	// compute challenge
	c = hFunc.Sum()
	// verify params
	verifyRemoveLiquidityParams(api, *proof, tool, h)
	// verify enc
	var l1, r1 Point
	l1 = tool.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 = tool.Add(proof.A_CLPL_Delta, tool.ScalarMul(proof.C_u_LP_Delta.CL, c))
	IsPointEqual(api, proof.IsEnabled, l1, r1)
	// verify ownership
	//var l2, r2 Point
	//l2 = tool.ScalarBaseMul(proof.Z_sk_u)
	//r2 = tool.Add(proof.A_pk_u, tool.ScalarMul(proof.Pk_u, c))
	//IsPointEqual(api, proof.IsEnabled, l2, r2)
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
	C_feeDeltaR := tool.ScalarMul(tool.Neg(h), proof.GasFee)
	C_feeRPrime := tool.Add(proof.C_fee.CR, C_feeDeltaR)
	C_feePrime := ElGamalEncConstraints{CL: proof.C_fee.CL, CR: C_feeRPrime}
	C_feePrimeNeg := tool.NegElgamal(C_feePrime)
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	//l4 := tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_fee), tool.ScalarMul(C_feePrimeNeg.CL, proof.Z_sk_uInv))
	//r4 := tool.Add(proof.A_T_feeC_feeRPrimeInv, tool.ScalarMul(tool.Add(proof.T_fee, C_feePrimeNeg.CR), c))
	//IsPointEqual(api, proof.IsEnabled, l4, r4)
	// set common parts
	pkProofs[0] = SetPkProof(proof.Pk_u, proof.A_pk_u, proof.Z_sk_u, proof.Z_sk_uInv)
	for i := 1; i < MaxRangeProofCount; i++ {
		pkProofs[i] = pkProofs[0]
	}
	tProofs[0] = SetTProof(C_uLPPrimeNeg, proof.A_T_uLPC_uLPRPrimeInv, proof.Z_bar_r_LP, proof.T_uLP)
	tProofs[1] = SetTProof(C_feePrimeNeg, proof.A_T_feeC_feeRPrimeInv, proof.Z_bar_r_fee, proof.T_fee)
	for i := 1; i < MaxRangeProofCount; i++ {
		tProofs[i] = tProofs[0]
	}
	// set proof deltas
	proof.C_fee_DeltaForGas = ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: tool.Neg(C_feeDeltaR),
	}
	C_fee_DeltaForFrom := ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: C_feeDeltaR,
	}
	isSameAssetA := api.IsZero(api.Sub(proof.AssetAId, proof.GasFeeAssetId))
	isSameAssetA = api.And(isSameAssetA, proof.IsEnabled)
	isSameAssetB := api.IsZero(api.Sub(proof.AssetBId, proof.GasFeeAssetId))
	isSameAssetB = api.And(isSameAssetB, proof.IsEnabled)
	deltaA := SelectPoint(api, isSameAssetA, C_feeDeltaR, tool.ZeroPoint())
	deltaB := SelectPoint(api, isSameAssetB, C_feeDeltaR, tool.ZeroPoint())
	C_uA_Delta := proof.C_uA_Delta
	C_uB_Delta := proof.C_uB_Delta
	C_uA_Delta.CR = tool.Add(C_uA_Delta.CR, deltaA)
	C_uB_Delta.CR = tool.Add(C_uB_Delta.CR, deltaB)
	proof.C_uA_Delta = C_uA_Delta
	proof.C_uB_Delta = C_uB_Delta
	C_fee_DeltaForFrom = SelectElgamal(api, isSameAssetA, C_uA_Delta, C_fee_DeltaForFrom)
	C_fee_DeltaForFrom = SelectElgamal(api, isSameAssetB, C_uB_Delta, C_fee_DeltaForFrom)
	proof.C_fee_DeltaForFrom = C_fee_DeltaForFrom
	return c, pkProofs, tProofs
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
	api.AssertIsLessOrEqual(Delta_LPCheck, LPCheck)
}

func SetEmptyRemoveLiquidityProofWitness() (witness RemoveLiquidityProofConstraints) {
	// valid enc
	witness.A_CLPL_Delta, _ = SetPointWitness(BasePoint)
	witness.A_CLPR_DeltaHExp_DeltaLPNeg, _ = SetPointWitness(BasePoint)
	witness.Z_rDelta_LP = ZeroInt
	// ownership
	witness.A_pk_u, _ = SetPointWitness(BasePoint)
	witness.A_T_uLPC_uLPRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_sk_u = ZeroInt
	witness.Z_bar_r_LP = ZeroInt
	witness.Z_sk_uInv = ZeroInt
	// common inputs
	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_pool_A, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_pool_B, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_u_LP, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_u_LP_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.Pk_pool, _ = SetPointWitness(BasePoint)
	witness.Pk_u, _ = SetPointWitness(BasePoint)
	witness.T_uLP, _ = SetPointWitness(BasePoint)
	witness.R_poolA = ZeroInt
	witness.R_poolB = ZeroInt
	witness.R_DeltaA = ZeroInt
	witness.R_DeltaB = ZeroInt
	witness.B_pool_A = ZeroInt
	witness.B_pool_B = ZeroInt
	witness.B_A_Delta = ZeroInt
	witness.B_B_Delta = ZeroInt
	witness.MinB_A_Delta = ZeroInt
	witness.MinB_B_Delta = ZeroInt
	witness.Delta_LP = ZeroInt
	witness.P = ZeroInt
	witness.AssetAId = ZeroInt
	witness.AssetBId = ZeroInt
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_bar_r_fee = ZeroInt
	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.T_fee, _ = SetPointWitness(BasePoint)
	witness.GasFeeAssetId = ZeroInt
	witness.GasFee = ZeroInt
	witness.C_fee_DeltaForFrom, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_fee_DeltaForGas, _ = SetElGamalEncWitness(ZeroElgamalEnc)
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
	witness.Z_rDelta_LP = proof.Z_rDelta_LP
	// ownership
	witness.A_pk_u, err = SetPointWitness(proof.A_pk_u)
	if err != nil {
		return witness, err
	}
	witness.A_T_uLPC_uLPRPrimeInv, err = SetPointWitness(proof.A_T_uLPC_uLPRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_sk_u = proof.Z_sk_u
	witness.Z_bar_r_LP = proof.Z_bar_r_LP
	witness.Z_sk_uInv = proof.Z_sk_uInv
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
	witness.R_poolA = proof.R_poolA
	witness.R_poolB = proof.R_poolB
	witness.R_DeltaA = proof.R_DeltaA
	witness.R_DeltaB = proof.R_DeltaB
	witness.B_pool_A = proof.B_pool_A
	witness.B_pool_B = proof.B_pool_B
	witness.B_A_Delta = proof.B_A_Delta
	witness.B_B_Delta = proof.B_B_Delta
	witness.MinB_A_Delta = proof.MinB_A_Delta
	witness.MinB_B_Delta = proof.MinB_B_Delta
	witness.Delta_LP = proof.Delta_LP
	witness.P = proof.P
	witness.AssetAId = uint64(proof.AssetAId)
	witness.AssetBId = uint64(proof.AssetBId)
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, err = SetPointWitness(proof.A_T_feeC_feeRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_bar_r_fee = proof.Z_bar_r_fee
	witness.C_fee, err = SetElGamalEncWitness(proof.C_fee)
	if err != nil {
		return witness, err
	}
	witness.T_fee, err = SetPointWitness(proof.T_fee)
	if err != nil {
		return witness, err
	}
	witness.GasFeeAssetId = uint64(proof.GasFeeAssetId)
	witness.GasFee = proof.GasFee
	hFee := curve.ScalarMul(curve.H, big.NewInt(int64(proof.GasFee)))
	if proof.GasFeeAssetId == proof.AssetAId {
		witness.C_fee_DeltaForFrom, err = SetElGamalEncWitness(proof.C_uA_Delta)
		if err != nil {
			return witness, err
		}
	} else if proof.GasFeeAssetId == proof.AssetBId {
		witness.C_fee_DeltaForFrom, err = SetElGamalEncWitness(proof.C_uB_Delta)
		if err != nil {
			return witness, err
		}
	} else {
		witness.C_fee_DeltaForFrom, err = SetElGamalEncWitness(&twistedElgamal.ElGamalEnc{
			CL: curve.ZeroPoint(),
			CR: curve.Neg(hFee),
		})
		if err != nil {
			return witness, err
		}
	}
	witness.C_fee_DeltaForGas, err = SetElGamalEncWitness(&twistedElgamal.ElGamalEnc{
		CL: curve.ZeroPoint(),
		CR: hFee,
	})
	if err != nil {
		return witness, err
	}
	witness.IsEnabled = SetBoolWitness(isEnabled)

	return witness, nil
}
