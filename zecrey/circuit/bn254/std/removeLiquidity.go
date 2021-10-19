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
	// valid Enc
	A_CLPL_Delta                Point
	A_CLPR_DeltaHExp_DeltaLPNeg Point
	Z_rDelta_LP                 Variable
	// ownership
	A_pk_u, A_T_uLPC_uLPRPrimeInv Point
	Z_sk_u, Z_bar_r_LP, Z_sk_uInv Variable
	// range proofs
	//LPRangeProof CtRangeProofConstraints
	// common inputs
	LC_Dao_A, LC_Dao_B           ElGamalEncConstraints
	C_uA_Delta, C_uB_Delta       ElGamalEncConstraints
	LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	C_u_LP                       ElGamalEncConstraints
	C_u_LP_Delta                 ElGamalEncConstraints
	Pk_Dao, Pk_u                 Point
	T_uLP                        Point
	R_DaoA, R_DaoB               Variable
	R_DeltaA, R_DeltaB           Variable
	B_Dao_A, B_Dao_B             Variable
	B_A_Delta, B_B_Delta         Variable
	Delta_LP                     Variable
	P                            Variable
	AssetAId, AssetBId           Variable
	IsEnabled                    Variable
}

// define tests for verifying the swap proof
func (circuit RemoveLiquidityProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
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
	VerifyRemoveLiquidityProof(cs, circuit, params, hFunc, H)

	return nil
}

func VerifyRemoveLiquidityProof(
	cs *ConstraintSystem,
	proof RemoveLiquidityProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
	h Point,
) {
	//IsPointEqual(cs, proof.IsEnabled, proof.T_uLP, proof.LPRangeProof.A)
	var (
		C_uLPPrime    ElGamalEncConstraints
		C_uLPPrimeNeg ElGamalEncConstraints
		c             Variable
	)
	// mimc
	//LPhFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	//if err != nil {
	//	return
	//}
	//VerifyCtRangeProof(cs, proof.LPRangeProof, params, LPhFunc)
	hFunc.Write(FixedCurveParam(cs))
	writePointIntoBuf(&hFunc, proof.Pk_u)
	writePointIntoBuf(&hFunc, proof.Pk_Dao)
	writeEncIntoBuf(&hFunc, proof.C_u_LP)
	writeEncIntoBuf(&hFunc, proof.C_uA_Delta)
	writeEncIntoBuf(&hFunc, proof.C_uB_Delta)
	writeEncIntoBuf(&hFunc, proof.C_u_LP_Delta)
	writePointIntoBuf(&hFunc, proof.T_uLP)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
	writePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_pk_u)
	writePointIntoBuf(&hFunc, proof.A_T_uLPC_uLPRPrimeInv)
	// compute challenge
	c = hFunc.Sum()
	// verify params
	verifyRemoveLiquidityParams(cs, proof, params, h)
	// verify Enc
	var l1, r1 Point
	l1.ScalarMulNonFixedBase(cs, &proof.Pk_u, proof.Z_rDelta_LP, params)
	r1.ScalarMulNonFixedBase(cs, &proof.C_u_LP_Delta.CL, c, params)
	r1.AddGeneric(cs, &r1, &proof.A_CLPL_Delta, params)
	IsPointEqual(cs, proof.IsEnabled, l1, r1)
	// verify ownership
	var l2, r2 Point
	l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_sk_u, params)
	r2.ScalarMulNonFixedBase(cs, &proof.Pk_u, c, params)
	r2.AddGeneric(cs, &r2, &proof.A_pk_u, params)
	IsPointEqual(cs, proof.IsEnabled, l2, r2)

	C_uLPPrime = EncSub(cs, proof.C_u_LP, proof.C_u_LP_Delta, params)
	C_uLPPrimeNeg = NegElgamal(cs, C_uLPPrime)
	var g_z_bar_r_LP, l3, r3 Point
	g_z_bar_r_LP.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_bar_r_LP, params)
	l3.ScalarMulNonFixedBase(cs, &C_uLPPrimeNeg.CL, proof.Z_sk_uInv, params)
	l3.AddGeneric(cs, &l3, &g_z_bar_r_LP, params)
	r3.AddGeneric(cs, &proof.T_uLP, &C_uLPPrimeNeg.CR, params)
	r3.ScalarMulNonFixedBase(cs, &r3, c, params)
	r3.AddGeneric(cs, &r3, &proof.A_T_uLPC_uLPRPrimeInv, params)
	IsPointEqual(cs, proof.IsEnabled, l3, r3)
}

func verifyRemoveLiquidityParams(
	cs *ConstraintSystem,
	proof RemoveLiquidityProofConstraints,
	params twistededwards.EdCurve,
	h Point,
) {
	var C_uA_Delta, C_uB_Delta, LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	C_uA_Delta = Enc(cs, h, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_u, params)
	C_uB_Delta = Enc(cs, h, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_u, params)
	LC_DaoA_Delta.CL.ScalarMulNonFixedBase(cs, &proof.Pk_Dao, proof.R_DeltaA, params)
	LC_DaoA_Delta.CR = C_uA_Delta.CR
	LC_DaoB_Delta.CL.ScalarMulNonFixedBase(cs, &proof.Pk_Dao, proof.R_DeltaB, params)
	LC_DaoB_Delta.CR = C_uB_Delta.CR
	IsElGamalEncEqual(cs, proof.IsEnabled, C_uA_Delta, proof.C_uA_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, C_uB_Delta, proof.C_uB_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, LC_DaoA_Delta, proof.LC_DaoA_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, LC_DaoB_Delta, proof.LC_DaoB_Delta)
	// verify LP
	deltaLP := cs.Mul(proof.Delta_LP, proof.Delta_LP)
	deltaLPCheck := cs.Mul(proof.B_A_Delta, proof.B_B_Delta)
	cs.AssertIsLessOrEqual(deltaLP, deltaLPCheck)
	// verify AMM info & DAO balance info
	l := cs.Mul(proof.B_A_Delta, proof.B_B_Delta)
	cs.AssertIsLessOrEqual(deltaLP, l)
}

func SetEmptyRemoveLiquidityProofWitness() (witness RemoveLiquidityProofConstraints) {
	witness.A_CLPL_Delta, _ = SetPointWitness(BasePoint)

	witness.A_CLPR_DeltaHExp_DeltaLPNeg, _ = SetPointWitness(BasePoint)

	// response
	witness.Z_rDelta_LP.Assign(ZeroInt)
	witness.A_pk_u, _ = SetPointWitness(BasePoint)

	witness.A_T_uLPC_uLPRPrimeInv, _ = SetPointWitness(BasePoint)

	witness.Z_sk_u.Assign(ZeroInt)
	witness.Z_bar_r_LP.Assign(ZeroInt)
	witness.Z_sk_uInv.Assign(ZeroInt)
	//witness.LPRangeProof, _ = SetCtRangeProofWitness(LPRangeProof, isEnabled)
	//if err != nil {
	//	return witness, _
	//}
	// common inputs
	witness.LC_Dao_A, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.LC_Dao_B, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_uA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_uB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.LC_DaoA_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.LC_DaoB_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_u_LP, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.C_u_LP_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

	witness.Pk_Dao, _ = SetPointWitness(BasePoint)

	witness.Pk_u, _ = SetPointWitness(BasePoint)

	witness.T_uLP, _ = SetPointWitness(BasePoint)

	witness.R_DaoA.Assign(ZeroInt)
	witness.R_DaoB.Assign(ZeroInt)
	witness.R_DeltaA.Assign(ZeroInt)
	witness.R_DeltaB.Assign(ZeroInt)
	witness.B_Dao_A.Assign(ZeroInt)
	witness.B_Dao_B.Assign(ZeroInt)
	witness.B_A_Delta.Assign(ZeroInt)
	witness.B_B_Delta.Assign(ZeroInt)
	witness.Delta_LP.Assign(ZeroInt)
	witness.P.Assign(ZeroInt)

	witness.AssetAId.Assign(ZeroInt)
	witness.AssetBId.Assign(ZeroInt)
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

	witness.A_CLPL_Delta, err = SetPointWitness(proof.A_CLPL_Delta)
	if err != nil {
		return witness, err
	}
	witness.A_CLPR_DeltaHExp_DeltaLPNeg, err = SetPointWitness(proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_rDelta_LP.Assign(proof.Z_rDelta_LP)
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
	//witness.LPRangeProof, err = SetCtRangeProofWitness(proof.LPRangeProof, isEnabled)
	//if err != nil {
	//	return witness, err
	//}
	// common inputs
	witness.LC_Dao_A, err = SetElGamalEncWitness(proof.LC_Dao_A)
	if err != nil {
		return witness, err
	}
	witness.LC_Dao_B, err = SetElGamalEncWitness(proof.LC_Dao_B)
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
	witness.LC_DaoA_Delta, err = SetElGamalEncWitness(proof.LC_DaoA_Delta)
	if err != nil {
		return witness, err
	}
	witness.LC_DaoB_Delta, err = SetElGamalEncWitness(proof.LC_DaoB_Delta)
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
	witness.Pk_Dao, err = SetPointWitness(proof.Pk_Dao)
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
	witness.R_DaoA.Assign(proof.R_DaoA)
	witness.R_DaoB.Assign(proof.R_DaoB)
	witness.R_DeltaA.Assign(proof.R_DeltaA)
	witness.R_DeltaB.Assign(proof.R_DeltaB)
	witness.B_Dao_A.Assign(proof.B_Dao_A)
	witness.B_Dao_B.Assign(proof.B_Dao_B)
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.Delta_LP.Assign(proof.Delta_LP)
	witness.P.Assign(proof.P)
	witness.AssetAId.Assign(uint64(proof.AssetAId))
	witness.AssetBId.Assign(uint64(proof.AssetBId))
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
