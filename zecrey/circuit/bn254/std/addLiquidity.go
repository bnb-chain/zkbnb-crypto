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

//
//type AddLiquidityProofConstraints struct {
//	// valid Enc
//	A_CLPL_Delta                Point
//	A_CLPR_DeltaHExp_DeltaLPNeg Point
//	Z_rDelta_LP                 Variable
//	// ownership
//	A_pk_u, A_T_uAC_uARPrimeInv, A_T_uBC_uBRPrimeInv Point
//	Z_sk_u, Z_bar_r_A, Z_bar_r_B, Z_sk_uInv          Variable
//	// range proofs
//	//ARangeProof, BRangeProof CtRangeProofConstraints
//	// common inputs
//	C_uA, C_uB                   ElGamalEncConstraints
//	C_uA_Delta, C_uB_Delta       ElGamalEncConstraints
//	LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
//	C_LP_Delta                   ElGamalEncConstraints
//	Pk_u, Pk_Dao                 Point
//	R_DeltaA, R_DeltaB           Variable
//	T_uA, T_uB                   Point
//	B_DaoA, B_DaoB               Variable
//	B_A_Delta, B_B_Delta         Variable
//	Delta_LP                     Variable
//	IsEnabled                    Variable
//}
//
//// define tests for verifying the swap proof
//func (circuit AddLiquidityProofConstraints) Define(curveID ecc.ID, api API) error {
//	// first check if C = c_1 \oplus c_2
//	// get edwards curve params
//	params, err := twistededwards.NewEdCurve(curveID)
//	if err != nil {
//		return err
//	}
//	// verify H
//	H := Point{
//		X: api.Constant(HX),
//		Y: api.Constant(HY),
//	}
//	// mimc
//	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, api)
//	if err != nil {
//		return err
//	}
//	VerifyAddLiquidityProof(api, circuit, params, hFunc, H)
//
//	return nil
//}
//
//func VerifyAddLiquidityProof(
//	api API,
//	proof AddLiquidityProofConstraints,
//	params twistededwards.EdCurve,
//	hFunc MiMC,
//	h Point,
//) {
//	//IsPointEqual(api, proof.IsEnabled, proof.T_uA, proof.ARangeProof.A)
//	//IsPointEqual(api, proof.IsEnabled, proof.T_uB, proof.BRangeProof.A)
//	var (
//		C_uAPrime, C_uBPrime       ElGamalEncConstraints
//		C_uAPrimeNeg, C_uBPrimeNeg ElGamalEncConstraints
//		c                          Variable
//	)
//	// mimc
//	//AhFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, api)
//	//if err != nil {
//	//	return
//	//}
//	//VerifyCtRangeProof(api, proof.ARangeProof, params, AhFunc)
//	//BhFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, api)
//	//if err != nil {
//	//	return
//	//}
//	//VerifyCtRangeProof(api, proof.BRangeProof, params, BhFunc)
//	// challenge buf
//	hFunc.Write(FixedCurveParam(api))
//	writePointIntoBuf(&hFunc, proof.Pk_u)
//	writePointIntoBuf(&hFunc, proof.Pk_Dao)
//	writeEncIntoBuf(&hFunc, proof.C_uA)
//	writeEncIntoBuf(&hFunc, proof.C_uB)
//	writeEncIntoBuf(&hFunc, proof.C_uA_Delta)
//	writeEncIntoBuf(&hFunc, proof.C_uB_Delta)
//	writeEncIntoBuf(&hFunc, proof.C_LP_Delta)
//	writePointIntoBuf(&hFunc, proof.T_uA)
//	writePointIntoBuf(&hFunc, proof.T_uB)
//	// write into buf
//	writePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
//	writePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
//	// write into buf
//	writePointIntoBuf(&hFunc, proof.A_pk_u)
//	writePointIntoBuf(&hFunc, proof.A_T_uAC_uARPrimeInv)
//	writePointIntoBuf(&hFunc, proof.A_T_uBC_uBRPrimeInv)
//	// compute challenge
//	c = hFunc.Sum()
//	// verify params
//	verifyAddLiquidityParams(
//		api,
//		proof,
//		params,
//		h,
//	)
//	// verify Enc
//	var l1, r1 Point
//	l1.ScalarMulNonFixedBase(api, &proof.Pk_u, proof.Z_rDelta_LP, params)
//	r1.ScalarMulNonFixedBase(api, &proof.C_LP_Delta.CL, c, params)
//	r1.AddGeneric(api, &r1, &proof.A_CLPL_Delta, params)
//	IsPointEqual(api, proof.IsEnabled, l1, r1)
//	// verify ownership
//	var l2, r2 Point
//	l2.ScalarMulFixedBase(api, params.BaseX, params.BaseY, proof.Z_sk_u, params)
//	r2.ScalarMulNonFixedBase(api, &proof.Pk_u, c, params)
//	r2.AddGeneric(api, &r2, &proof.A_pk_u, params)
//	IsPointEqual(api, proof.IsEnabled, l2, r2)
//	C_uAPrime = EncSub(api, proof.C_uA, proof.C_uA_Delta, params)
//	C_uBPrime = EncSub(api, proof.C_uB, proof.C_uB_Delta, params)
//	C_uAPrimeNeg = NegElgamal(api, C_uAPrime)
//	C_uBPrimeNeg = NegElgamal(api, C_uBPrime)
//	var g_z_bar_r_A, l3, r3 Point
//	g_z_bar_r_A.ScalarMulFixedBase(api, params.BaseX, params.BaseY, proof.Z_bar_r_A, params)
//	l3.ScalarMulNonFixedBase(api, &C_uAPrimeNeg.CL, proof.Z_sk_uInv, params)
//	l3.AddGeneric(api, &l3, &g_z_bar_r_A, params)
//	r3.AddGeneric(api, &proof.T_uA, &C_uAPrimeNeg.CR, params)
//	r3.ScalarMulNonFixedBase(api, &r3, c, params)
//	r3.AddGeneric(api, &r3, &proof.A_T_uAC_uARPrimeInv, params)
//	IsPointEqual(api, proof.IsEnabled, l3, r3)
//	// l4,r4
//	var g_z_bar_r_B, l4, r4 Point
//	g_z_bar_r_B.ScalarMulFixedBase(api, params.BaseX, params.BaseY, proof.Z_bar_r_B, params)
//	l4.ScalarMulNonFixedBase(api, &C_uBPrimeNeg.CL, proof.Z_sk_uInv, params)
//	l4.AddGeneric(api, &l4, &g_z_bar_r_B, params)
//	r4.AddGeneric(api, &proof.T_uB, &C_uBPrimeNeg.CR, params)
//	r4.ScalarMulNonFixedBase(api, &r4, c, params)
//	r4.AddGeneric(api, &r4, &proof.A_T_uBC_uBRPrimeInv, params)
//	IsPointEqual(api, proof.IsEnabled, l4, r4)
//}
//
//func verifyAddLiquidityParams(
//	api API,
//	proof AddLiquidityProofConstraints,
//	params twistededwards.EdCurve,
//	h Point,
//) {
//	var C_uA_Delta, C_uB_Delta, LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
//	C_uA_Delta = Enc(api, h, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_u, params)
//	C_uB_Delta = Enc(api, h, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_u, params)
//	LC_DaoA_Delta.CL.ScalarMulNonFixedBase(api, &proof.Pk_Dao, proof.R_DeltaA, params)
//	LC_DaoA_Delta.CR = C_uA_Delta.CR
//	LC_DaoB_Delta.CL.ScalarMulNonFixedBase(api, &proof.Pk_Dao, proof.R_DeltaB, params)
//	LC_DaoB_Delta.CR = C_uB_Delta.CR
//	IsElGamalEncEqual(api, proof.IsEnabled, C_uA_Delta, proof.C_uA_Delta)
//	IsElGamalEncEqual(api, proof.IsEnabled, C_uB_Delta, proof.C_uB_Delta)
//	IsElGamalEncEqual(api, proof.IsEnabled, LC_DaoA_Delta, proof.LC_DaoA_Delta)
//	IsElGamalEncEqual(api, proof.IsEnabled, LC_DaoB_Delta, proof.LC_DaoB_Delta)
//	// verify LP
//	deltaLP := api.Mul(proof.Delta_LP, proof.Delta_LP)
//	deltaLPCheck := api.Mul(proof.B_A_Delta, proof.B_B_Delta)
//	IsVariableEqual(api, proof.IsEnabled, deltaLP, deltaLPCheck)
//	// verify AMM info & DAO balance info
//	l := api.Mul(proof.B_DaoB, proof.B_A_Delta)
//	r := api.Mul(proof.B_DaoA, proof.B_B_Delta)
//	IsVariableEqual(api, proof.IsEnabled, l, r)
//}
//
//func SetEmptyAddLiquidityProofWitness() (witness AddLiquidityProofConstraints) {
//	witness.A_CLPL_Delta, _ = SetPointWitness(BasePoint)
//
//	witness.A_CLPR_DeltaHExp_DeltaLPNeg, _ = SetPointWitness(BasePoint)
//
//	// response
//	witness.Z_rDelta_LP.Assign(ZeroInt)
//	witness.A_pk_u, _ = SetPointWitness(BasePoint)
//
//	witness.A_T_uAC_uARPrimeInv, _ = SetPointWitness(BasePoint)
//
//	witness.A_T_uBC_uBRPrimeInv, _ = SetPointWitness(BasePoint)
//
//	witness.Z_sk_u.Assign(ZeroInt)
//	witness.Z_bar_r_A.Assign(ZeroInt)
//	witness.Z_bar_r_B.Assign(ZeroInt)
//	witness.Z_sk_uInv.Assign(ZeroInt)
//	//witness.ARangeProof, _ = SetCtRangeProofWitness(ARangeProof, isEnabled)
//	//if err != nil {
//	//	return witness, _
//	//}
//	//witness.BRangeProof, _ = SetCtRangeProofWitness(BRangeProof, isEnabled)
//	//if err != nil {
//	//	return witness, _
//	//}
//	// common inputs
//	witness.C_uA, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.C_uB, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.LC_DaoA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.LC_DaoB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.C_LP_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
//
//	witness.Pk_Dao, _ = SetPointWitness(BasePoint)
//
//	witness.Pk_u, _ = SetPointWitness(BasePoint)
//
//	witness.R_DeltaA.Assign(ZeroInt)
//	witness.R_DeltaB.Assign(ZeroInt)
//	witness.T_uA, _ = SetPointWitness(BasePoint)
//
//	witness.T_uB, _ = SetPointWitness(BasePoint)
//
//	witness.B_DaoA.Assign(ZeroInt)
//	witness.B_DaoB.Assign(ZeroInt)
//	witness.B_A_Delta.Assign(ZeroInt)
//	witness.B_B_Delta.Assign(ZeroInt)
//	witness.Delta_LP.Assign(ZeroInt)
//
//	witness.IsEnabled = SetBoolWitness(false)
//	return witness
//}
//
//// set the witness for swap proof
//func SetAddLiquidityProofWitness(proof *zecrey.AddLiquidityProof, isEnabled bool) (witness AddLiquidityProofConstraints, err error) {
//	if proof == nil {
//		log.Println("[SetWithdrawProofWitness] invalid params")
//		return witness, err
//	}
//
//	// proof must be correct
//	verifyRes, err := proof.Verify()
//	if err != nil {
//		log.Println("[SetWithdrawProofWitness] invalid proof:", err)
//		return witness, err
//	}
//	if !verifyRes {
//		log.Println("[SetWithdrawProofWitness] invalid proof")
//		return witness, errors.New("[SetWithdrawProofWitness] invalid proof")
//	}
//
//	witness.A_CLPL_Delta, err = SetPointWitness(proof.A_CLPL_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.A_CLPR_DeltaHExp_DeltaLPNeg, err = SetPointWitness(proof.A_CLPR_DeltaHExp_DeltaLPNeg)
//	if err != nil {
//		return witness, err
//	}
//	// response
//	witness.Z_rDelta_LP.Assign(proof.Z_rDelta_LP)
//	witness.A_pk_u, err = SetPointWitness(proof.A_pk_u)
//	if err != nil {
//		return witness, err
//	}
//	witness.A_T_uAC_uARPrimeInv, err = SetPointWitness(proof.A_T_uAC_uARPrimeInv)
//	if err != nil {
//		return witness, err
//	}
//	witness.A_T_uBC_uBRPrimeInv, err = SetPointWitness(proof.A_T_uBC_uBRPrimeInv)
//	if err != nil {
//		return witness, err
//	}
//	witness.Z_sk_u.Assign(proof.Z_sk_u)
//	witness.Z_bar_r_A.Assign(proof.Z_bar_r_A)
//	witness.Z_bar_r_B.Assign(proof.Z_bar_r_B)
//	witness.Z_sk_uInv.Assign(proof.Z_sk_uInv)
//	//witness.ARangeProof, err = SetCtRangeProofWitness(proof.ARangeProof, isEnabled)
//	//if err != nil {
//	//	return witness, err
//	//}
//	//witness.BRangeProof, err = SetCtRangeProofWitness(proof.BRangeProof, isEnabled)
//	//if err != nil {
//	//	return witness, err
//	//}
//	// common inputs
//	witness.C_uA, err = SetElGamalEncWitness(proof.C_uA)
//	if err != nil {
//		return witness, err
//	}
//	witness.C_uB, err = SetElGamalEncWitness(proof.C_uB)
//	if err != nil {
//		return witness, err
//	}
//	witness.C_uA_Delta, err = SetElGamalEncWitness(proof.C_uA_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.C_uB_Delta, err = SetElGamalEncWitness(proof.C_uB_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.LC_DaoA_Delta, err = SetElGamalEncWitness(proof.LC_DaoA_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.LC_DaoB_Delta, err = SetElGamalEncWitness(proof.LC_DaoB_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.C_LP_Delta, err = SetElGamalEncWitness(proof.C_LP_Delta)
//	if err != nil {
//		return witness, err
//	}
//	witness.Pk_Dao, err = SetPointWitness(proof.Pk_Dao)
//	if err != nil {
//		return witness, err
//	}
//	witness.Pk_u, err = SetPointWitness(proof.Pk_u)
//	if err != nil {
//		return witness, err
//	}
//	witness.R_DeltaA.Assign(proof.R_DeltaA)
//	witness.R_DeltaB.Assign(proof.R_DeltaB)
//	witness.T_uA, err = SetPointWitness(proof.T_uA)
//	if err != nil {
//		return witness, err
//	}
//	witness.T_uB, err = SetPointWitness(proof.T_uB)
//	if err != nil {
//		return witness, err
//	}
//	witness.B_DaoA.Assign(proof.B_DaoA)
//	witness.B_DaoB.Assign(proof.B_DaoB)
//	witness.B_A_Delta.Assign(proof.B_A_Delta)
//	witness.B_B_Delta.Assign(proof.B_B_Delta)
//	witness.Delta_LP.Assign(proof.Delta_LP)
//	witness.IsEnabled = SetBoolWitness(isEnabled)
//	return witness, nil
//}
