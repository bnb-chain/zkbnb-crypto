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
	// valid Enc
	A_C_ufeeL_Delta, A_CufeeR_DeltaHExpb_fee_DeltaInv Point
	Z_r_Deltafee                                      Variable
	// Ownership
	A_pk_u, A_T_uAC_uARPrimeInv, A_T_ufeeC_ufeeRPrimeInv Point
	Z_sk_u, Z_bar_r_A, Z_bar_r_fee, Z_sk_uInv            Variable
	// range proofs
	ARangeProof   CtRangeProofConstraints
	FeeRangeProof CtRangeProofConstraints
	// common inputs
	// user asset A balance enc
	C_uA ElGamalEncConstraints
	// user asset fee balance enc
	C_ufee ElGamalEncConstraints
	// user asset fee Delta enc
	C_ufee_Delta ElGamalEncConstraints
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta ElGamalEncConstraints
	// liquidity pool asset A,B Delta enc
	LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	// public keys
	Pk_Dao, Pk_u Point
	// random value for Delta A & B
	R_DeltaA, R_DeltaB Variable
	// commitment for user asset A & fee
	T_uA, T_ufee Point
	// liquidity pool asset B balance
	LC_DaoB ElGamalEncConstraints
	// random value for dao liquidity asset B
	R_DaoB Variable
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_Delta, B_B_Delta, B_fee_Delta Variable
	B_DaoA, B_DaoB                    Variable
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha, Beta Variable
	Gamma       Variable
	// generators
	G, H                           Point
	IsEnabled                      Variable
	AssetAId, AssetBId, AssetFeeId Variable
}

// define tests for verifying the swap proof
func (circuit *SwapProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}
	VerifySwapProof(cs, *circuit, params, hFunc)

	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@cs: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifySwapProof(
	cs *ConstraintSystem,
	proof SwapProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
) {
	var (
		C_uAPrime, C_ufeePrime       ElGamalEncConstraints
		C_uAPrimeNeg, C_ufeePrimeNeg ElGamalEncConstraints
		c                            Variable
	)
	// mimc
	ARangeFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	if err != nil {
		return
	}
	feeRangeFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
	if err != nil {
		return
	}
	verifyCtRangeProof(cs, proof.ARangeProof, params, ARangeFunc)
	verifyCtRangeProof(cs, proof.FeeRangeProof, params, feeRangeFunc)
	// challenge buf
	writePointIntoBuf(&hFunc, proof.G)
	writePointIntoBuf(&hFunc, proof.H)
	writePointIntoBuf(&hFunc, proof.Pk_u)
	writePointIntoBuf(&hFunc, proof.Pk_Dao)
	writeEncIntoBuf(&hFunc, proof.C_uA)
	writeEncIntoBuf(&hFunc, proof.C_ufee)
	writeEncIntoBuf(&hFunc, proof.C_uA_Delta)
	writeEncIntoBuf(&hFunc, proof.C_ufee_Delta)
	writePointIntoBuf(&hFunc, proof.T_uA)
	writePointIntoBuf(&hFunc, proof.T_ufee)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_C_ufeeL_Delta)
	writePointIntoBuf(&hFunc, proof.A_CufeeR_DeltaHExpb_fee_DeltaInv)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_pk_u)
	writePointIntoBuf(&hFunc, proof.A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&hFunc, proof.A_T_ufeeC_ufeeRPrimeInv)
	// compute challenge
	c = hFunc.Sum()
	// TODO verify params
	verifySwapParams(cs, proof, proof.IsEnabled, params)
	// verify enc
	var l1, r1 Point
	l1.ScalarMulNonFixedBase(cs, &proof.Pk_u, proof.Z_r_Deltafee, params)
	r1.ScalarMulNonFixedBase(cs, &proof.C_ufee_Delta.CL, c, params)
	r1.AddGeneric(cs, &r1, &proof.A_C_ufeeL_Delta, params)
	IsPointEqual(cs, proof.IsEnabled, l1, r1)
	// verify ownership
	// l2,r2
	var l2, r2 Point
	l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_sk_u, params)
	r2.ScalarMulNonFixedBase(cs, &proof.Pk_u, c, params)
	r2.AddGeneric(cs, &r2, &proof.A_pk_u, params)
	IsPointEqual(cs, proof.IsEnabled, l2, r2)
	C_uAPrime = encSub(cs, proof.C_uA, proof.C_uA_Delta, params)
	assetDelta := cs.Sub(proof.AssetAId, proof.AssetFeeId)
	isSameAsset := cs.IsZero(assetDelta)
	C_uAPrime2 := encSub(cs, C_uAPrime, proof.C_ufee_Delta, params)
	C_uAPrime = selectElgamal(cs, isSameAsset, C_uAPrime2, C_uAPrime)
	C_ufeePrime = encSub(cs, proof.C_ufee, proof.C_ufee_Delta, params)
	C_ufeePrime = selectElgamal(cs, isSameAsset, C_uAPrime, C_ufeePrime)
	C_uAPrimeNeg = negElgamal(cs, C_uAPrime)
	C_ufeePrimeNeg = negElgamal(cs, C_ufeePrime)
	// l3,r3
	var g_z_bar_r_A, l3, r3 Point
	g_z_bar_r_A.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_bar_r_A, params)
	l3.ScalarMulNonFixedBase(cs, &C_uAPrimeNeg.CL, proof.Z_sk_uInv, params)
	l3.AddGeneric(cs, &l3, &g_z_bar_r_A, params)
	r3.AddGeneric(cs, &proof.T_uA, &C_uAPrimeNeg.CR, params)
	r3.ScalarMulNonFixedBase(cs, &r3, c, params)
	r3.AddGeneric(cs, &r3, &proof.A_T_uAC_uARPrimeInv, params)
	IsPointEqual(cs, proof.IsEnabled, l3, r3)

	// l4,r4
	var g_z_bar_r_fee, l4, r4 Point
	g_z_bar_r_fee.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_bar_r_fee, params)
	l4.ScalarMulNonFixedBase(cs, &C_ufeePrimeNeg.CL, proof.Z_sk_uInv, params)
	l4.AddGeneric(cs, &l4, &g_z_bar_r_fee, params)
	r4.AddGeneric(cs, &proof.T_ufee, &C_ufeePrimeNeg.CR, params)
	r4.ScalarMulNonFixedBase(cs, &r4, c, params)
	r4.AddGeneric(cs, &r4, &proof.A_T_ufeeC_ufeeRPrimeInv, params)
	IsPointEqual(cs, proof.IsEnabled, l4, r4)
}

/*
	verifyCorrectEnc verify the encryption
	@cs: the constraint system
	@h,pk,CStar: public inputs
	@bStar: the value
	@rStar: the random value
	@params: params for the curve tebn254
*/
func verifyCorrectEnc1(
	cs *ConstraintSystem,
	h, pk Point,
	receiverPk Point,
	CStar ElGamalEncConstraints,
	receiverCStar ElGamalEncConstraints,
	bStar Variable,
	fee Variable,
	rStar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	// check sender
	var CL, CR, gr Point
	// C_L = pk^r
	CL.ScalarMulNonFixedBase(cs, &pk, rStar, params)
	// C_R = g^r h^b
	gr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, rStar, params)
	hNeg := Neg(cs, h, params)
	deltaBalance := cs.Add(bStar, fee)
	CR.ScalarMulNonFixedBase(cs, hNeg, deltaBalance, params)
	CR.AddGeneric(cs, &gr, &CR, params)

	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, CStar)

	// check receiver
	CL.ScalarMulNonFixedBase(cs, &receiverPk, rStar, params)
	CR.ScalarMulNonFixedBase(cs, &h, deltaBalance, params)
	CR.AddGeneric(cs, &gr, &CR, params)
	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, receiverCStar)
}

/*
	verifyCorrectEnc verify the encryption
	@cs: the constraint system
	@h,pk,CStar: public inputs
	@bStar: the value
	@rStar: the random value
	@params: params for the curve tebn254
*/
func verifyCorrectEnc2(
	cs *ConstraintSystem,
	h, pk Point,
	receiverPk Point,
	CStar ElGamalEncConstraints,
	receiverCStar ElGamalEncConstraints,
	bStar Variable,
	rStar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	// check sender
	var CL, CR, gr Point
	// C_L = pk^r
	CL.ScalarMulNonFixedBase(cs, &pk, rStar, params)
	// C_R = g^r h^b
	gr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, rStar, params)
	hNeg := Neg(cs, h, params)
	CR.ScalarMulNonFixedBase(cs, hNeg, bStar, params)
	CR.AddGeneric(cs, &gr, &CR, params)

	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, CStar)

	// check receiver
	CL.ScalarMulNonFixedBase(cs, &receiverPk, rStar, params)
	CR.ScalarMulNonFixedBase(cs, &h, bStar, params)
	CR.AddGeneric(cs, &gr, &CR, params)
	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, receiverCStar)
}

// set the witness for swap proof
func SetSwapProofWitness(proof *zecrey.SwapProof, isEnabled bool) (witness SwapProofConstraints, err error) {
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
		return witness, ErrInvalidProof
	}

	witness.A_C_ufeeL_Delta, err = SetPointWitness(proof.A_C_ufeeL_Delta)
	if err != nil {
		return witness, err
	}
	witness.A_CufeeR_DeltaHExpb_fee_DeltaInv, err = SetPointWitness(proof.A_CufeeR_DeltaHExpb_fee_DeltaInv)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_r_Deltafee.Assign(proof.Z_r_Deltafee)
	witness.A_pk_u, err = SetPointWitness(proof.A_pk_u)
	if err != nil {
		return witness, err
	}
	witness.A_T_uAC_uARPrimeInv, err = SetPointWitness(proof.A_T_uAC_uARPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.A_T_ufeeC_ufeeRPrimeInv, err = SetPointWitness(proof.A_T_ufeeC_ufeeRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_sk_u.Assign(proof.Z_sk_u)
	witness.Z_bar_r_A.Assign(proof.Z_bar_r_A)
	witness.Z_bar_r_fee.Assign(proof.Z_bar_r_fee)
	witness.Z_sk_uInv.Assign(proof.Z_sk_uInv)
	witness.ARangeProof, err = setCtRangeProofWitness(proof.ARangeProof, isEnabled)
	if err != nil {
		return witness, err
	}
	witness.FeeRangeProof, err = setCtRangeProofWitness(proof.FeeRangeProof, isEnabled)
	if err != nil {
		return witness, err
	}
	// common inputs
	witness.C_uA, err = SetElGamalEncWitness(proof.C_uA)
	if err != nil {
		return witness, err
	}
	witness.C_ufee, err = SetElGamalEncWitness(proof.C_ufee)
	if err != nil {
		return witness, err
	}
	witness.C_ufee_Delta, err = SetElGamalEncWitness(proof.C_ufee_Delta)
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
	witness.T_ufee, err = SetPointWitness(proof.T_ufee)
	if err != nil {
		return witness, err
	}
	witness.LC_DaoB, err = SetElGamalEncWitness(proof.LC_DaoB)
	if err != nil {
		return witness, err
	}
	witness.R_DaoB.Assign(proof.R_DaoB)
	witness.B_A_Delta.Assign(proof.B_A_Delta)
	witness.B_B_Delta.Assign(proof.B_B_Delta)
	witness.B_fee_Delta.Assign(proof.B_fee_Delta)
	witness.B_DaoA.Assign(proof.B_DaoA)
	witness.B_DaoB.Assign(proof.B_DaoB)
	witness.Alpha.Assign(proof.Alpha)
	witness.Beta.Assign(proof.Beta)
	witness.Gamma.Assign(uint64(proof.Gamma))
	witness.G, err = SetPointWitness(proof.G)
	if err != nil {
		return witness, err
	}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.AssetAId.Assign(uint64(proof.AssetAId))
	witness.AssetBId.Assign(uint64(proof.AssetBId))
	witness.AssetFeeId.Assign(uint64(proof.AssetFeeId))
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

func verifySwapParams(
	cs *ConstraintSystem,
	proof SwapProofConstraints,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var C_uA_Delta, C_uB_Delta, LC_DaoA_Delta, LC_DaoB_Delta ElGamalEncConstraints
	C_uA_Delta = enc(cs, proof.H, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_u, params)
	C_uB_Delta = enc(cs, proof.H, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_u, params)
	LC_DaoA_Delta = enc(cs, proof.H, proof.B_A_Delta, proof.R_DeltaA, proof.Pk_Dao, params)
	LC_DaoB_Delta = enc(cs, proof.H, proof.B_B_Delta, proof.R_DeltaB, proof.Pk_Dao, params)
	IsElGamalEncEqual(cs, isEnabled, C_uA_Delta, proof.C_uA_Delta)
	IsElGamalEncEqual(cs, isEnabled, C_uB_Delta, proof.C_uB_Delta)
	IsElGamalEncEqual(cs, isEnabled, LC_DaoA_Delta, proof.LC_DaoA_Delta)
	IsElGamalEncEqual(cs, isEnabled, LC_DaoB_Delta, proof.LC_DaoB_Delta)
	// TODO verify AMM info & DAO balance info
	cs.AssertIsLessOrEqual(proof.B_B_Delta, proof.B_DaoB)
}
