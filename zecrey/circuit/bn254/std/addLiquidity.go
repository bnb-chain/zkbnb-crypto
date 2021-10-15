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
	// range proofs
	ARangeProof, BRangeProof CtRangeProofConstraints
	// common inputs
	C_uA, C_uB                   ElGamalEncConstraints
	C_uA_Delta, C_uB_Delta       ElGamalEncConstraints
	LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	C_LP_Delta                   ElGamalEncConstraints
	Pk_u, Pk_Dao                 Point
	R_DeltaA, R_DeltaB           Variable
	T_uA, T_uB                   Point
	B_DaoA, B_DaoB               Variable
	B_A_Delta, B_B_Delta         Variable
	Delta_LP                     Variable
	G, H                         Point
	IsEnabled                    Variable
}

// define tests for verifying the swap proof
func (circuit AddLiquidityProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
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
	IsPointEqual(cs, circuit.IsEnabled, H, circuit.H)
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}
	VerifyAddLiquidityProof(cs, circuit, params, hFunc)

	return nil
}

func VerifyAddLiquidityProof(
	cs *ConstraintSystem,
	proof AddLiquidityProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
) {
	IsPointEqual(cs, proof.IsEnabled, proof.T_uA, proof.ARangeProof.A)
	IsPointEqual(cs, proof.IsEnabled, proof.T_uB, proof.BRangeProof.A)
	var (
		C_uAPrime, C_uBPrime       ElGamalEncConstraints
		C_uAPrimeNeg, C_uBPrimeNeg ElGamalEncConstraints
		c                          Variable
	)
	// mimc
	AhFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	if err != nil {
		return
	}
	verifyCtRangeProof(cs, proof.ARangeProof, params, AhFunc)
	BhFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	if err != nil {
		return
	}
	verifyCtRangeProof(cs, proof.BRangeProof, params, BhFunc)
	// challenge buf
	writePointIntoBuf(&hFunc, proof.G)
	writePointIntoBuf(&hFunc, proof.H)
	writePointIntoBuf(&hFunc, proof.Pk_u)
	writePointIntoBuf(&hFunc, proof.Pk_Dao)
	writeEncIntoBuf(&hFunc, proof.C_uA)
	writeEncIntoBuf(&hFunc, proof.C_uB)
	writeEncIntoBuf(&hFunc, proof.C_uA_Delta)
	writeEncIntoBuf(&hFunc, proof.C_uB_Delta)
	writeEncIntoBuf(&hFunc, proof.C_LP_Delta)
	writePointIntoBuf(&hFunc, proof.T_uA)
	writePointIntoBuf(&hFunc, proof.T_uB)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_CLPL_Delta)
	writePointIntoBuf(&hFunc, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_pk_u)
	writePointIntoBuf(&hFunc, proof.A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&hFunc, proof.A_T_uBC_uBRPrimeInv)
	// compute challenge
	c = hFunc.Sum()
	// verify params
	verifyAddLiquidityParams(
		cs,
		proof,
		params,
	)
	// verify enc
	var l1, r1 Point
	l1.ScalarMulNonFixedBase(cs, &proof.Pk_u, proof.Z_rDelta_LP, params)
	r1.ScalarMulNonFixedBase(cs, &proof.C_LP_Delta.CL, c, params)
	r1.AddGeneric(cs, &r1, &proof.A_CLPL_Delta, params)
	IsPointEqual(cs, proof.IsEnabled, l1, r1)
	// verify ownership
	var l2, r2 Point
	l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_sk_u, params)
	r2.ScalarMulNonFixedBase(cs, &proof.Pk_u, c, params)
	r2.AddGeneric(cs, &r2, &proof.A_pk_u, params)
	IsPointEqual(cs, proof.IsEnabled, l2, r2)
	C_uAPrime = encSub(cs, proof.C_uA, proof.C_uA_Delta, params)
	C_uBPrime = encSub(cs, proof.C_uB, proof.C_uB_Delta, params)
	C_uAPrimeNeg = negElgamal(cs, C_uAPrime)
	C_uBPrimeNeg = negElgamal(cs, C_uBPrime)
	var g_z_bar_r_A, l3, r3 Point
	g_z_bar_r_A.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_bar_r_A, params)
	l3.ScalarMulNonFixedBase(cs, &C_uAPrimeNeg.CL, proof.Z_sk_uInv, params)
	l3.AddGeneric(cs, &l3, &g_z_bar_r_A, params)
	r3.AddGeneric(cs, &proof.T_uA, &C_uAPrimeNeg.CR, params)
	r3.ScalarMulNonFixedBase(cs, &r3, c, params)
	r3.AddGeneric(cs, &r3, &proof.A_T_uAC_uARPrimeInv, params)
	IsPointEqual(cs, proof.IsEnabled, l3, r3)
	// l4,r4
	var g_z_bar_r_B, l4, r4 Point
	g_z_bar_r_B.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_bar_r_B, params)
	l4.ScalarMulNonFixedBase(cs, &C_uBPrimeNeg.CL, proof.Z_sk_uInv, params)
	l4.AddGeneric(cs, &l4, &g_z_bar_r_B, params)
	r4.AddGeneric(cs, &proof.T_uB, &C_uBPrimeNeg.CR, params)
	r4.ScalarMulNonFixedBase(cs, &r4, c, params)
	r4.AddGeneric(cs, &r4, &proof.A_T_uBC_uBRPrimeInv, params)
	IsPointEqual(cs, proof.IsEnabled, l4, r4)
}

func verifyAddLiquidityParams(
	cs *ConstraintSystem,
	proof AddLiquidityProofConstraints,
	params twistededwards.EdCurve,
) {
	var C_uA_Delta, C_uB_Delta, LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	C_uA_Delta = enc(cs, proof.H, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_u, params)
	C_uB_Delta = enc(cs, proof.H, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_u, params)
	LC_DaoA_Delta = enc(cs, proof.H, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_Dao, params)
	LC_DaoB_Delta = enc(cs, proof.H, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_Dao, params)
	IsElGamalEncEqual(cs, proof.IsEnabled, C_uA_Delta, proof.C_uA_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, C_uB_Delta, proof.C_uB_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, LC_DaoA_Delta, proof.LC_DaoA_Delta)
	IsElGamalEncEqual(cs, proof.IsEnabled, LC_DaoB_Delta, proof.LC_DaoB_Delta)
	// verify LP
	deltaLP := cs.Mul(proof.Delta_LP, proof.Delta_LP)
	deltaLPCheck := cs.Mul(proof.B_A_Delta, proof.B_B_Delta)
	IsVariableEqual(cs, proof.IsEnabled, deltaLP, deltaLPCheck)
	// verify AMM info & DAO balance info
	l := cs.Mul(proof.B_DaoB, proof.B_A_Delta)
	r := cs.Mul(proof.B_DaoA, proof.B_B_Delta)
	IsVariableEqual(cs, proof.IsEnabled, l, r)
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
	witness.ARangeProof, err = SetCtRangeProofWitness(proof.ARangeProof, isEnabled)
	if err != nil {
		return witness, err
	}
	witness.BRangeProof, err = SetCtRangeProofWitness(proof.BRangeProof, isEnabled)
	if err != nil {
		return witness, err
	}
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
	witness.LC_DaoA_Delta, err = SetElGamalEncWitness(proof.LC_DaoA_Delta)
	if err != nil {
		return witness, err
	}
	witness.LC_DaoB_Delta, err = SetElGamalEncWitness(proof.LC_DaoB_Delta)
	if err != nil {
		return witness, err
	}
	witness.C_LP_Delta, err = SetElGamalEncWitness(proof.C_LP_Delta)
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
	witness.B_DaoA.Assign(proof.B_DaoA)
	witness.B_DaoB.Assign(proof.B_DaoB)
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.Delta_LP.Assign(proof.Delta_LP)
	witness.G, err = SetPointWitness(proof.G)
	if err != nil {
		return witness, err
	}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
