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

// SwapProof in circuit
type SwapProofConstraints struct {
	// commitments
	// Ownership
	A_pk_u, A_T_uAC_uARPrimeInv  Point
	Z_sk_u, Z_bar_r_A, Z_sk_uInv Variable
	// common inputs
	// user asset A balance enc
	C_uA ElGamalEncConstraints
	// treasury asset fee Delta enc
	C_treasuryfee_Delta ElGamalEncConstraints
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta ElGamalEncConstraints
	// liquidity pool asset A,B Delta enc
	LC_poolA_Delta, LC_poolB_Delta ElGamalEncConstraints
	// public keys
	Pk_pool, Pk_u, Pk_treasury Point
	// random value for Delta A & B
	R_DeltaA, R_DeltaB, R_Deltafee Variable
	// commitment for user asset A & fee
	T_uA Point
	// asset A,B,fee Delta & pool liquidity asset B balance
	B_A_Delta, B_B_Delta, B_treasuryfee_Delta Variable
	B_poolA, B_poolB                          Variable
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	Alpha Variable
	// gamma = 10000 - fee
	Gamma Variable
	// asset a id
	AssetAId Variable
	// asset b id
	AssetBId     Variable
	MinB_B_Delta Variable
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
func (circuit SwapProofConstraints) Define(curveID ecc.ID, api API) error {
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
	VerifySwapProof(tool, api, circuit, hFunc, H)

	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@api: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifySwapProof(
	tool *EccTool,
	api API,
	proof SwapProofConstraints,
	hFunc MiMC,
	h Point,
) (c Variable, pkProofs [MaxRangeProofCount]CommonPkProof, tProofs [MaxRangeProofCount]CommonTProof) {
	// challenge buf
	hFunc.Write(FixedCurveParam(api))
	hFunc.Write(proof.AssetAId)
	hFunc.Write(proof.AssetBId)
	WritePointIntoBuf(&hFunc, proof.Pk_u)
	WriteEncIntoBuf(&hFunc, proof.C_uA)
	WriteEncIntoBuf(&hFunc, proof.C_uA_Delta)
	WritePointIntoBuf(&hFunc, proof.T_uA)
	hFunc.Write(proof.B_A_Delta)
	hFunc.Write(proof.MinB_B_Delta)
	hFunc.Write(proof.B_treasuryfee_Delta)
	// write into buf
	// gas fee
	WritePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	WriteEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)
	// write into buf
	WritePointIntoBuf(&hFunc, proof.A_pk_u)
	WritePointIntoBuf(&hFunc, proof.A_T_uAC_uARPrimeInv)
	// compute challenge
	c = hFunc.Sum()
	// verify params
	verifySwapParams(api, proof, proof.IsEnabled, tool, h)
	// verify ownership
	var l1, r1 Point
	l1 = tool.ScalarBaseMul(proof.Z_sk_u)
	r1 = tool.Add(proof.A_pk_u, tool.ScalarMul(proof.Pk_u, c))
	IsPointEqual(api, proof.IsEnabled, l1, r1)
	// check if gas fee asset id is the same as asset a
	assetDiff := api.Sub(proof.GasFeeAssetId, proof.AssetAId)
	isSameAsset := api.IsZero(assetDiff)
	var hNeg Point
	hNeg.Neg(api, &h)
	// if same, check params
	IsElGamalEncEqual(api, isSameAsset, proof.C_uA, proof.C_fee)
	IsPointEqual(api, isSameAsset, proof.A_T_uAC_uARPrimeInv, proof.A_T_feeC_feeRPrimeInv)
	C_uAPrime := tool.EncAdd(proof.C_uA, proof.C_uA_Delta)
	deltaFee := tool.ScalarMul(hNeg, proof.GasFee)
	deltaA := SelectPoint(api, isSameAsset, deltaFee, zeroPoint(api))
	C_uAPrime.CR = tool.Add(C_uAPrime.CR, deltaA)
	C_uAPrimeNeg := tool.NegElgamal(C_uAPrime)
	//var l3, r3 Point
	//l3 = tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_A), tool.ScalarMul(C_uAPrimeNeg.CL, proof.Z_sk_uInv))
	//r3 = tool.Add(proof.A_T_uAC_uARPrimeInv, tool.ScalarMul(tool.Add(proof.T_uA, C_uAPrimeNeg.CR), c))
	//IsPointEqual(api, proof.IsEnabled, l3, r3)
	// fee
	C_feeRPrime := tool.Add(proof.C_fee.CR, deltaFee)
	C_feePrime := ElGamalEncConstraints{CL: proof.C_fee.CL, CR: C_feeRPrime}
	C_feePrimeNeg := tool.NegElgamal(C_feePrime)
	C_feePrimeNeg = SelectElgamal(api, isSameAsset, C_uAPrimeNeg, C_feePrimeNeg)
	//var l4, r4 Point
	//l4 = tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_fee), tool.ScalarMul(C_feePrimeNeg.CL, proof.Z_sk_uInv))
	//r4 = tool.Add(proof.A_T_feeC_feeRPrimeInv, tool.ScalarMul(tool.Add(proof.T_fee, C_feePrimeNeg.CR), c))
	//IsPointEqual(api, proof.IsEnabled, l4, r4)
	// set common parts
	pkProofs[0] = SetPkProof(proof.Pk_u, proof.A_pk_u, proof.Z_sk_u, proof.Z_sk_uInv)
	for i := 1; i < MaxRangeProofCount; i++ {
		pkProofs[i] = pkProofs[0]
	}
	tProofs[0] = SetTProof(C_uAPrimeNeg, proof.A_T_uAC_uARPrimeInv, proof.Z_bar_r_A, proof.T_uA)
	tProofs[1] = SetTProof(C_feePrimeNeg, proof.A_T_feeC_feeRPrimeInv, proof.Z_bar_r_fee, proof.T_fee)
	for i := 1; i < MaxRangeProofCount; i++ {
		tProofs[i] = tProofs[0]
	}
	return c, pkProofs, tProofs
}

func SetEmptySwapProofWitness() (witness SwapProofConstraints) {
	// Ownership
	witness.A_pk_u, _ = SetPointWitness(BasePoint)

	witness.A_T_uAC_uARPrimeInv, _ = SetPointWitness(BasePoint)

	witness.Z_sk_u.Assign(ZeroInt)
	witness.Z_bar_r_A.Assign(ZeroInt)
	witness.Z_sk_uInv.Assign(ZeroInt)
	// common inputs
	witness.C_uA, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_treasuryfee_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.LC_poolB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	// public keys
	witness.Pk_pool, _ = SetPointWitness(BasePoint)
	witness.Pk_u, _ = SetPointWitness(BasePoint)
	witness.Pk_treasury, _ = SetPointWitness(BasePoint)
	// random value for Delta A & B
	witness.R_DeltaA.Assign(ZeroInt)
	witness.R_DeltaB.Assign(ZeroInt)
	witness.R_Deltafee.Assign(ZeroInt)
	// commitment for user asset A & fee
	witness.T_uA, _ = SetPointWitness(BasePoint)
	// asset A,B,fee Delta & pool liquidity asset B balance
	witness.B_A_Delta.Assign(ZeroInt)
	witness.B_B_Delta.Assign(ZeroInt)
	witness.B_treasuryfee_Delta.Assign(ZeroInt)
	witness.B_poolA.Assign(ZeroInt)
	witness.B_poolB.Assign(ZeroInt)
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 10000 - fee
	witness.Alpha.Assign(ZeroInt)
	witness.Gamma.Assign(ZeroInt)
	// asset a id
	// asset b id
	witness.AssetAId.Assign(ZeroInt)
	witness.AssetBId.Assign(ZeroInt)
	witness.MinB_B_Delta.Assign(ZeroInt)
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
func SetSwapProofWitness(proof *zecrey.SwapProof, isEnabled bool) (witness SwapProofConstraints, err error) {
	if proof == nil {
		log.Println("[SetSwapProofWitness] invalid params")
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetSwapProofWitness] invalid proof:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetSwapProofWitness] invalid proof")
		return witness, errors.New("[SetSwapProofWitness] invalid proof")
	}

	// Ownership
	witness.A_pk_u, err = SetPointWitness(proof.A_pk_u)
	if err != nil {
		return witness, err
	}
	witness.A_T_uAC_uARPrimeInv, err = SetPointWitness(proof.A_T_uAC_uARPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_sk_u.Assign(proof.Z_sk_u)
	witness.Z_bar_r_A.Assign(proof.Z_bar_r_A)
	witness.Z_sk_uInv.Assign(proof.Z_sk_uInv)
	// common inputs
	witness.C_uA, err = SetElGamalEncWitness(proof.C_uA)
	if err != nil {
		return witness, err
	}
	witness.C_treasuryfee_Delta, err = SetElGamalEncWitness(proof.C_treasuryfee_Delta)
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
	// public keys
	witness.Pk_pool, err = SetPointWitness(proof.Pk_pool)
	if err != nil {
		return witness, err
	}
	witness.Pk_u, err = SetPointWitness(proof.Pk_u)
	if err != nil {
		return witness, err
	}
	witness.Pk_treasury, err = SetPointWitness(proof.Pk_treasury)
	if err != nil {
		return witness, err
	}
	// random value for Delta A & B
	witness.R_DeltaA.Assign(proof.R_DeltaA)
	witness.R_DeltaB.Assign(proof.R_DeltaB)
	witness.R_Deltafee.Assign(proof.R_Deltafee)
	// commitment for user asset A & fee
	witness.T_uA, err = SetPointWitness(proof.T_uA)
	if err != nil {
		return witness, err
	}
	// asset A,B,fee Delta & pool liquidity asset B balance
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.B_treasuryfee_Delta.Assign(proof.B_treasuryfee_Delta)
	witness.B_poolA.Assign(proof.B_poolA)
	witness.B_poolB.Assign(proof.B_poolB)
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 10000 - fee
	witness.Alpha.Assign(proof.Alpha)
	witness.Gamma.Assign(uint64(proof.Gamma))
	// asset a id
	// asset b id
	witness.AssetAId.Assign(uint64(proof.AssetAId))
	witness.AssetBId.Assign(uint64(proof.AssetBId))
	witness.MinB_B_Delta.Assign(proof.MinB_B_Delta)
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

func verifySwapParams(
	api API,
	proof SwapProofConstraints,
	isEnabled Variable,
	tool *EccTool,
	h Point,
) {
	api.AssertIsLessOrEqual(proof.MinB_B_Delta, proof.B_B_Delta)
	// pk^r
	CL1 := tool.ScalarMul(proof.Pk_u, proof.R_DeltaA)
	// g^r h^b
	var hb1Neg Point
	hb1 := tool.ScalarMul(h, proof.B_A_Delta)
	hb1Neg.Neg(api, &hb1)
	B_poolA_Delta := api.Sub(proof.B_A_Delta, proof.B_treasuryfee_Delta)
	hbpool := tool.ScalarMul(h, B_poolA_Delta)
	gr1 := tool.ScalarBaseMul(proof.R_DeltaA)
	C_uA_Delta := ElGamalEncConstraints{
		CL: CL1,
		CR: tool.Add(gr1, hb1Neg),
	}
	// pk^r
	CL2 := tool.ScalarMul(proof.Pk_u, proof.R_DeltaB)
	// g^r h^b
	var hb2Neg Point
	hb2 := tool.ScalarMul(h, proof.B_B_Delta)
	hb2Neg.Neg(api, &hb2)
	gr2 := tool.ScalarBaseMul(proof.R_DeltaB)
	C_uB_Delta := ElGamalEncConstraints{
		CL: CL2,
		CR: tool.Add(gr2, hb2),
	}
	LC_poolA_Delta := ElGamalEncConstraints{
		CL: tool.ScalarMul(proof.Pk_pool, proof.R_DeltaA),
		CR: tool.Add(gr1, hbpool),
	}
	LC_poolB_Delta := ElGamalEncConstraints{
		CL: tool.ScalarMul(proof.Pk_pool, proof.R_DeltaB),
		CR: tool.Add(gr2, hb2Neg),
	}
	IsElGamalEncEqual(api, isEnabled, C_uA_Delta, proof.C_uA_Delta)
	IsElGamalEncEqual(api, isEnabled, C_uB_Delta, proof.C_uB_Delta)
	IsElGamalEncEqual(api, isEnabled, LC_poolA_Delta, proof.LC_poolA_Delta)
	IsElGamalEncEqual(api, isEnabled, LC_poolB_Delta, proof.LC_poolB_Delta)
	api.AssertIsLessOrEqual(proof.B_B_Delta, proof.B_poolB)
	//alphaGamma := ffmath.Multiply(big.NewInt(int64(proof.Alpha)), big.NewInt(int64(proof.Gamma)))
	//deltaBCheck := ffmath.Multiply(
	//	alphaGamma,
	//	big.NewInt(int64(proof.B_poolB)))
	//deltaBCheck = ffmath.Div(deltaBCheck, ffmath.Add(big.NewInt(int64(OneMillion*TenThousand)), alphaGamma))
	//if deltaBCheck.Cmp(big.NewInt(int64(proof.B_B_Delta))) < 0 {
	//	return false, nil
	//}
	k := api.Mul(proof.B_poolA, proof.B_poolB)
	poolADelta := api.Sub(proof.B_A_Delta, proof.B_treasuryfee_Delta)
	kPrime := api.Mul(api.Add(proof.B_poolA, poolADelta), api.Sub(proof.B_poolB, proof.B_B_Delta))
	api.AssertIsLessOrEqual(k, kPrime)
}
