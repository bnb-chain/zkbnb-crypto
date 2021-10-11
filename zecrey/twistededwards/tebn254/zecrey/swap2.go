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

package zecrey

import (
	"bytes"
	"errors"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func ProveSwap(relation *SwapProofRelation) (proof *SwapProof2, err error) {
	// check params
	if relation == nil {
		return nil, errors.New("[ProveSwap] invalid relation params")
	}
	var (
		alpha_r_Deltafee                                          *big.Int
		alpha_sk_u, alpha_sk_uInv, alpha_bar_r_A, alpha_bar_r_fee *big.Int
		A_C_ufeeL_Delta, A_CufeeR_DeltaHb_fee_DeltaInv            *Point
		A_Pk_u, A_T_ufeeC_ufeeRPrimeInv, A_T_uAC_uARPrimeInv      *Point
		c                                                         *big.Int
		Z_r_Deltafee, Z_sk_u, Z_bar_r_A, Z_bar_r_fee, Z_sk_uInv   *big.Int
		buf                                                       bytes.Buffer
	)
	// challenge buf
	writePointIntoBuf(&buf, relation.G)
	writePointIntoBuf(&buf, relation.H)
	writePointIntoBuf(&buf, relation.Pk_u)
	writePointIntoBuf(&buf, relation.Pk_Dao)
	writeEncIntoBuf(&buf, relation.C_uA)
	writeEncIntoBuf(&buf, relation.C_ufee)
	writeEncIntoBuf(&buf, relation.C_uA_Delta)
	writeEncIntoBuf(&buf, relation.C_ufee_Delta)
	writePointIntoBuf(&buf, relation.T_uA)
	writePointIntoBuf(&buf, relation.T_ufee)
	// valid enc
	alpha_r_Deltafee = curve.RandomValue()
	A_C_ufeeL_Delta = curve.ScalarMul(relation.Pk_u, alpha_r_Deltafee)
	A_CufeeR_DeltaHb_fee_DeltaInv = curve.ScalarMul(relation.G, alpha_r_Deltafee)
	// write into buf
	writePointIntoBuf(&buf, A_C_ufeeL_Delta)
	writePointIntoBuf(&buf, A_CufeeR_DeltaHb_fee_DeltaInv)
	// ownership
	alpha_sk_u = curve.RandomValue()
	alpha_sk_uInv = ffmath.ModInverse(alpha_sk_u, Order)
	alpha_bar_r_A = curve.RandomValue()
	alpha_bar_r_fee = curve.RandomValue()
	A_Pk_u = curve.ScalarMul(relation.G, alpha_sk_u)
	// if asset fee id == asset A id, construct two same value proofs
	if relation.AssetFeeId == relation.AssetAId {
		CLDelta := curve.Add(
			curve.Neg(relation.C_uA_Delta.CL),
			curve.Neg(relation.C_ufee_Delta.CL),
		)
		// user asset A & fee part
		A_T_uAC_uARPrimeInv = curve.Add(
			relation.C_uA.CL,
			CLDelta,
		)
		A_T_uAC_uARPrimeInv = curve.Neg(A_T_uAC_uARPrimeInv)
		A_T_uAC_uARPrimeInv = curve.ScalarMul(A_T_uAC_uARPrimeInv, alpha_sk_uInv)
		A_T_uAC_uARPrimeInv = curve.Add(A_T_uAC_uARPrimeInv, curve.ScalarMul(relation.G, alpha_bar_r_A))
		// user asset fee part
		A_T_ufeeC_ufeeRPrimeInv = curve.Add(
			relation.C_ufee.CL,
			CLDelta,
		)
		A_T_ufeeC_ufeeRPrimeInv = curve.Neg(A_T_ufeeC_ufeeRPrimeInv)
		A_T_ufeeC_ufeeRPrimeInv = curve.ScalarMul(A_T_ufeeC_ufeeRPrimeInv, alpha_sk_uInv)
		A_T_ufeeC_ufeeRPrimeInv = curve.Add(A_T_ufeeC_ufeeRPrimeInv, curve.ScalarMul(relation.G, alpha_bar_r_fee))
	} else {
		// user asset A part
		A_T_uAC_uARPrimeInv = curve.Add(
			relation.C_uA.CL,
			curve.Neg(relation.C_uA_Delta.CL),
		)
		A_T_uAC_uARPrimeInv = curve.Neg(A_T_uAC_uARPrimeInv)
		A_T_uAC_uARPrimeInv = curve.ScalarMul(A_T_uAC_uARPrimeInv, alpha_sk_uInv)
		A_T_uAC_uARPrimeInv = curve.Add(A_T_uAC_uARPrimeInv, curve.ScalarMul(relation.G, alpha_bar_r_A))
		// user asset fee part
		A_T_ufeeC_ufeeRPrimeInv = curve.Add(
			relation.C_ufee.CL,
			curve.Neg(relation.C_ufee_Delta.CL),
		)
		A_T_ufeeC_ufeeRPrimeInv = curve.Neg(A_T_ufeeC_ufeeRPrimeInv)
		A_T_ufeeC_ufeeRPrimeInv = curve.ScalarMul(A_T_ufeeC_ufeeRPrimeInv, alpha_sk_uInv)
		A_T_ufeeC_ufeeRPrimeInv = curve.Add(A_T_ufeeC_ufeeRPrimeInv, curve.ScalarMul(relation.G, alpha_bar_r_fee))
	}
	// write into buf
	writePointIntoBuf(&buf, A_Pk_u)
	writePointIntoBuf(&buf, A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&buf, A_T_ufeeC_ufeeRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// compute response values
	Z_r_Deltafee = ffmath.AddMod(alpha_r_Deltafee, ffmath.Multiply(c, relation.R_Deltafee), Order)
	Z_sk_u = ffmath.AddMod(alpha_sk_u, ffmath.Multiply(c, relation.Sk_u), Order)
	if relation.AssetAId == relation.AssetFeeId {
		// construct responses
		Z_bar_r_A = ffmath.AddMod(ffmath.Add(alpha_bar_r_A, alpha_bar_r_fee),
			ffmath.Multiply(c, ffmath.Add(relation.Bar_r_A, relation.Bar_r_fee)), Order)
		Z_bar_r_fee = new(big.Int).Set(Z_bar_r_A)
	} else {
		// construct responses
		Z_bar_r_A = ffmath.AddMod(alpha_bar_r_A, ffmath.Multiply(c, relation.Bar_r_A), Order)
		Z_bar_r_fee = ffmath.AddMod(alpha_bar_r_fee, ffmath.Multiply(c, relation.Bar_r_fee), Order)
	}
	Z_sk_uInv = ffmath.AddMod(alpha_sk_uInv, ffmath.Multiply(c, ffmath.ModInverse(relation.Sk_u, Order)), Order)
	// construct proof
	proof = &SwapProof2{
		A_C_ufeeL_Delta:                  A_C_ufeeL_Delta,
		A_CufeeR_DeltaHExpb_fee_DeltaInv: A_CufeeR_DeltaHb_fee_DeltaInv,
		Z_r_Deltafee:                     Z_r_Deltafee,
		A_pk_u:                           A_Pk_u,
		A_T_uAC_uARPrimeInv:              A_T_uAC_uARPrimeInv,
		A_T_ufeeC_ufeeRPrimeInv:          A_T_ufeeC_ufeeRPrimeInv,
		Z_sk_u:                           Z_sk_u,
		Z_bar_r_A:                        Z_bar_r_A,
		Z_bar_r_fee:                      Z_bar_r_fee,
		Z_sk_uInv:                        Z_sk_uInv,
		ARangeProof:                      relation.ARangeProof,
		FeeRangeProof:                    relation.FeeRangeProof,
		C_uA:                          relation.C_uA,
		C_ufee:                        relation.C_ufee,
		C_ufee_Delta:                  relation.C_ufee_Delta,
		C_uA_Delta:                    relation.C_uA_Delta,
		C_uB_Delta:                    relation.C_uB_Delta,
		LC_DaoA_Delta:                 relation.LC_DaoA_Delta,
		LC_DaoB_Delta:                 relation.LC_DaoB_Delta,
		Pk_Dao:                        relation.Pk_Dao,
		Pk_u:                          relation.Pk_u,
		R_DeltaA:                      relation.R_DeltaA,
		R_DeltaB:                      relation.R_DeltaB,
		T_uA:                          relation.T_uA,
		T_ufee:                        relation.T_ufee,
		LC_DaoB:                       relation.LC_DaoB,
		R_DaoB:                        relation.R_DaoB,
		B_A_Delta:                     relation.B_A_Delta,
		B_B_Delta:                     relation.B_B_Delta,
		B_fee_Delta:                   relation.B_fee_Delta,
		B_DaoB:                        relation.B_DaoB,
		Alpha:                         relation.Alpha,
		Beta:                          relation.Beta,
		Gamma:                         relation.Gamma,
		G:                             relation.G,
		H:                             relation.H,
	}
	return proof, nil
}

func (proof *SwapProof2) Verify() (res bool, err error) {
	if proof == nil {
		return false, errors.New("[SwapProof2 Verify] invalid params")
	}
	var (
		C_uAPrime, C_ufeePrime       *ElGamalEnc
		C_uAPrimeNeg, C_ufeePrimeNeg *ElGamalEnc
		c                            *big.Int
		buf                          bytes.Buffer
	)
	// challenge buf
	writePointIntoBuf(&buf, proof.G)
	writePointIntoBuf(&buf, proof.H)
	writePointIntoBuf(&buf, proof.Pk_u)
	writePointIntoBuf(&buf, proof.Pk_Dao)
	writeEncIntoBuf(&buf, proof.C_uA)
	writeEncIntoBuf(&buf, proof.C_ufee)
	writeEncIntoBuf(&buf, proof.C_uA_Delta)
	writeEncIntoBuf(&buf, proof.C_ufee_Delta)
	writePointIntoBuf(&buf, proof.T_uA)
	writePointIntoBuf(&buf, proof.T_ufee)
	// write into buf
	writePointIntoBuf(&buf, proof.A_C_ufeeL_Delta)
	writePointIntoBuf(&buf, proof.A_CufeeR_DeltaHExpb_fee_DeltaInv)
	// write into buf
	writePointIntoBuf(&buf, proof.A_pk_u)
	writePointIntoBuf(&buf, proof.A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&buf, proof.A_T_ufeeC_ufeeRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// TODO verify params
	isValidParams, err := verifySwapParams(proof)
	if err != nil {
		return false, err
	}
	if !isValidParams {
		return false, errors.New("[SwapProof Verify] invalid params")
	}
	// verify enc
	l1 := curve.ScalarMul(proof.Pk_u, proof.Z_r_Deltafee)
	r1 := curve.Add(proof.A_C_ufeeL_Delta, curve.ScalarMul(proof.C_ufee_Delta.CL, c))
	if !l1.Equal(r1) {
		log.Println("[SwapProof Verify] l1 != r1")
		return false, nil
	}
	// verify ownership
	l2 := curve.ScalarMul(proof.G, proof.Z_sk_u)
	r2 := curve.Add(proof.A_pk_u, curve.ScalarMul(proof.Pk_u, c))
	if !l2.Equal(r2) {
		log.Println("[SwapProof Verify] l2 != r2")
		return false, nil
	}
	if equalEnc(proof.C_uA, proof.C_ufee) {
		C_uAPrime, err = twistedElgamal.EncSub(proof.C_uA, proof.C_uA_Delta)
		if err != nil {
			return false, err
		}
		C_uAPrime, err = twistedElgamal.EncSub(C_uAPrime, proof.C_ufee_Delta)
		if err != nil {
			return false, err
		}
		C_ufeePrime = C_uAPrime
	} else {
		C_uAPrime, err = twistedElgamal.EncSub(proof.C_uA, proof.C_uA_Delta)
		if err != nil {
			return false, err
		}
		C_ufeePrime, err = twistedElgamal.EncSub(proof.C_ufee, proof.C_ufee_Delta)
		if err != nil {
			return false, err
		}
	}
	C_uAPrimeNeg = negElgamal(C_uAPrime)
	C_ufeePrimeNeg = negElgamal(C_ufeePrime)
	l3 := curve.Add(
		curve.ScalarMul(curve.G, proof.Z_bar_r_A),
		curve.ScalarMul(C_uAPrimeNeg.CL, proof.Z_sk_uInv),
	)
	r3 := curve.Add(
		proof.A_T_uAC_uARPrimeInv,
		curve.ScalarMul(
			curve.Add(
				proof.T_uA,
				C_uAPrimeNeg.CR,
			),
			c,
		),
	)
	if !l3.Equal(r3) {
		log.Println("[SwapProof Verify] l3 != r3")
		return false, nil
	}
	l4 := curve.Add(
		curve.ScalarMul(curve.G, proof.Z_bar_r_fee),
		curve.ScalarMul(C_ufeePrimeNeg.CL, proof.Z_sk_uInv),
	)
	r4 := curve.Add(
		proof.A_T_ufeeC_ufeeRPrimeInv,
		curve.ScalarMul(
			curve.Add(
				proof.T_ufee,
				C_ufeePrimeNeg.CR,
			),
			c,
		),
	)
	if !l4.Equal(r4) {
		log.Println("[SwapProof Verify] l4 != r4")
		return false, nil
	}
	return true, nil
}

func verifySwapParams(proof *SwapProof2) (res bool, err error) {
	C_uA_Delta, err := twistedElgamal.Enc(big.NewInt(int64(proof.B_A_Delta)), proof.R_DeltaA, proof.Pk_u)
	if err != nil {
		return false, err
	}
	C_uB_Delta, err := twistedElgamal.Enc(big.NewInt(int64(proof.B_B_Delta)), proof.R_DeltaB, proof.Pk_u)
	if err != nil {
		return false, err
	}
	LC_DaoA_Delta, err := twistedElgamal.Enc(big.NewInt(int64(proof.B_A_Delta)), proof.R_DeltaA, proof.Pk_Dao)
	if err != nil {
		return false, err
	}
	LC_DaoB_Delta, err := twistedElgamal.Enc(big.NewInt(int64(proof.B_B_Delta)), proof.R_DeltaB, proof.Pk_Dao)
	if err != nil {
		return false, err
	}
	if !equalEnc(C_uA_Delta, proof.C_uA_Delta) || !equalEnc(C_uB_Delta, proof.C_uB_Delta) ||
		!equalEnc(LC_DaoA_Delta, proof.LC_DaoA_Delta) || !equalEnc(LC_DaoB_Delta, proof.LC_DaoB_Delta) {
		return false, nil
	}
	// TODO verify AMM info & DAO balance info
	return true, nil
}
