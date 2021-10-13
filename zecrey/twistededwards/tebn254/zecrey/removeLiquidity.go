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
	"math"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func ProveRemoveLiquidity(relation *RemoveLiquidityRelation) (proof *RemoveLiquidityProof, err error) {
	if relation == nil {
		log.Println("[ProveRemoveLiquidity] invalid params")
		return nil, errors.New("[ProveRemoveLiquidity] invalid params")
	}
	var (
		alpha_r_DeltaLP                           *big.Int
		A_CLPL_Delta, A_CLPR_DeltaHExp_DeltaLPNeg *Point
		alpha_sk_u, alpha_sk_uInv, alpha_bar_r_LP *big.Int
		A_pk_u, A_T_uLPC_uLPRPrimeInv             *Point
		c                                         *big.Int
		Z_rDeltaLP                                *big.Int
		Z_sk_u, Z_bar_r_LP, Z_sk_uInv             *big.Int
		buf                                       bytes.Buffer
	)
	writePointIntoBuf(&buf, relation.G)
	writePointIntoBuf(&buf, relation.H)
	writePointIntoBuf(&buf, relation.Pk_u)
	writePointIntoBuf(&buf, relation.Pk_Dao)
	writeEncIntoBuf(&buf, relation.C_u_LP)
	writeEncIntoBuf(&buf, relation.C_uA_Delta)
	writeEncIntoBuf(&buf, relation.C_uB_Delta)
	writeEncIntoBuf(&buf, relation.C_u_LP_Delta)
	writePointIntoBuf(&buf, relation.T_uLP)
	// valid enc
	alpha_r_DeltaLP = curve.RandomValue()
	A_CLPL_Delta = curve.ScalarMul(relation.Pk_u, alpha_r_DeltaLP)
	A_CLPR_DeltaHExp_DeltaLPNeg = curve.ScalarMul(relation.G, alpha_r_DeltaLP)
	// write into buf
	writePointIntoBuf(&buf, A_CLPL_Delta)
	writePointIntoBuf(&buf, A_CLPR_DeltaHExp_DeltaLPNeg)
	// ownership
	alpha_sk_u = curve.RandomValue()
	alpha_sk_uInv = ffmath.ModInverse(alpha_sk_u, Order)
	alpha_bar_r_LP = curve.RandomValue()
	A_pk_u = curve.ScalarMul(relation.G, alpha_sk_u)
	// user asset A part
	A_T_uLPC_uLPRPrimeInv = curve.Add(
		relation.C_u_LP.CL,
		curve.Neg(relation.C_u_LP_Delta.CL),
	)
	A_T_uLPC_uLPRPrimeInv = curve.Neg(A_T_uLPC_uLPRPrimeInv)
	A_T_uLPC_uLPRPrimeInv = curve.ScalarMul(A_T_uLPC_uLPRPrimeInv, alpha_sk_uInv)
	A_T_uLPC_uLPRPrimeInv = curve.Add(
		A_T_uLPC_uLPRPrimeInv,
		curve.ScalarMul(relation.G, alpha_bar_r_LP))
	// write into buf
	writePointIntoBuf(&buf, A_pk_u)
	writePointIntoBuf(&buf, A_T_uLPC_uLPRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// compute response values
	Z_rDeltaLP = ffmath.AddMod(alpha_r_DeltaLP, ffmath.Multiply(c, relation.R_DeltaLP), Order)
	Z_sk_u = ffmath.AddMod(alpha_sk_u, ffmath.Multiply(c, relation.Sk_u), Order)
	Z_bar_r_LP = ffmath.AddMod(alpha_bar_r_LP, ffmath.Multiply(c, relation.Bar_r_LP), Order)
	Z_sk_uInv = ffmath.AddMod(alpha_sk_uInv, ffmath.Multiply(c, ffmath.ModInverse(relation.Sk_u, Order)), Order)
	// construct proof
	proof = &RemoveLiquidityProof{
		A_CLPL_Delta:                A_CLPL_Delta,
		A_CLPR_DeltaHExp_DeltaLPNeg: A_CLPR_DeltaHExp_DeltaLPNeg,
		Z_rDelta_LP:                 Z_rDeltaLP,
		A_pk_u:                      A_pk_u,
		A_T_uLPC_uLPRPrimeInv:       A_T_uLPC_uLPRPrimeInv,
		Z_sk_u:                      Z_sk_u,
		Z_bar_r_LP:                  Z_bar_r_LP,
		Z_sk_uInv:                   Z_sk_uInv,
		LPRangeProof:                relation.LPRangeProof,
		LC_Dao_A:                    relation.LC_Dao_A,
		LC_Dao_B:                    relation.LC_Dao_B,
		C_uA_Delta:                  relation.C_uA_Delta,
		C_uB_Delta:                  relation.C_uB_Delta,
		LC_DaoA_Delta:               relation.LC_DaoA_Delta,
		LC_DaoB_Delta:               relation.LC_DaoB_Delta,
		Pk_Dao:                      relation.Pk_Dao,
		Pk_u:                        relation.Pk_u,
		R_DaoA:                      relation.R_DaoA,
		R_DaoB:                      relation.R_DaoB,
		R_DeltaA:                    relation.R_DeltaA,
		R_DeltaB:                    relation.R_DeltaB,
		B_Dao_A:                     relation.B_Dao_A,
		B_Dao_B:                     relation.B_Dao_B,
		B_A_Delta:                   relation.B_A_Delta,
		B_B_Delta:                   relation.B_B_Delta,
		Delta_LP:                    relation.Delta_LP,
		C_u_LP:                      relation.C_u_LP,
		C_u_LP_Delta:                relation.C_u_LP_Delta,
		P:                           relation.P,
		G:                           relation.G,
		H:                           relation.H,
		AssetAId:                    relation.AssetAId,
		AssetBId:                    relation.AssetBId,
		T_uLP:                       relation.T_uLP,
	}
	return proof, nil
}

func (proof *RemoveLiquidityProof) Verify() (res bool, err error) {
	if proof == nil {
		log.Println("[RemoveLiquidityProof Verify] err: invalid proof")
		return false, errors.New("[RemoveLiquidityProof Verify] err: invalid proof")
	}
	var (
		C_uLPPrime    *ElGamalEnc
		C_uLPPrimeNeg *ElGamalEnc
		c             *big.Int
		buf           bytes.Buffer
	)
	writePointIntoBuf(&buf, proof.G)
	writePointIntoBuf(&buf, proof.H)
	writePointIntoBuf(&buf, proof.Pk_u)
	writePointIntoBuf(&buf, proof.Pk_Dao)
	writeEncIntoBuf(&buf, proof.C_u_LP)
	writeEncIntoBuf(&buf, proof.C_uA_Delta)
	writeEncIntoBuf(&buf, proof.C_uB_Delta)
	writeEncIntoBuf(&buf, proof.C_u_LP_Delta)
	writePointIntoBuf(&buf, proof.T_uLP)
	// write into buf
	writePointIntoBuf(&buf, proof.A_CLPL_Delta)
	writePointIntoBuf(&buf, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&buf, proof.A_pk_u)
	writePointIntoBuf(&buf, proof.A_T_uLPC_uLPRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[RemoveLiquidityProof Verify] unable to compute challenge")
		return false, err
	}
	// verify params
	// verify params
	isValidParams, err := verifyRemoveLiquidityParams(proof)
	if err != nil {
		return false, err
	}
	if !isValidParams {
		return false, errors.New("[RemoveLiquidityProof Verify] invalid params")
	}
	// verify enc
	l1 := curve.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 := curve.Add(proof.A_CLPL_Delta, curve.ScalarMul(proof.C_u_LP_Delta.CL, c))
	if !l1.Equal(r1) {
		log.Println("[RemoveLiquidityProof Verify] l1 != r1")
		return false, nil
	}
	// verify ownership
	l2 := curve.ScalarMul(proof.G, proof.Z_sk_u)
	r2 := curve.Add(proof.A_pk_u, curve.ScalarMul(proof.Pk_u, c))
	if !l2.Equal(r2) {
		log.Println("[RemoveLiquidityProof Verify] l2 != r2")
		return false, nil
	}
	C_uLPPrime, err = twistedElgamal.EncSub(proof.C_u_LP, proof.C_u_LP_Delta)
	if err != nil {
		return false, err
	}
	C_uLPPrimeNeg = negElgamal(C_uLPPrime)
	l3 := curve.Add(
		curve.ScalarMul(proof.G, proof.Z_bar_r_LP),
		curve.ScalarMul(C_uLPPrimeNeg.CL, proof.Z_sk_uInv),
	)
	r3 := curve.Add(
		proof.A_T_uLPC_uLPRPrimeInv,
		curve.ScalarMul(
			curve.Add(
				proof.T_uLP,
				C_uLPPrimeNeg.CR,
			),
			c,
		),
	)
	if !l3.Equal(r3) {
		log.Println("[RemoveLiquidityProof Verify] l3 != r3")
		return false, nil
	}
	return true, nil
}

func verifyRemoveLiquidityParams(proof *RemoveLiquidityProof) (res bool, err error) {
	// check uint64 & int64
	if !validUint64(proof.B_A_Delta) || !validUint64(proof.B_B_Delta) || !validUint64(proof.Delta_LP) {
		log.Println("[verifyRemoveLiquidityParams] invalid params")
		return false, errors.New("[verifyRemoveLiquidityParams] invalid params")
	}
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
		log.Println("[verifyRemoveLiquidityParams] invalid balance enc")
		return false, nil
	}
	// verify LP
	Delta_LPCheck := uint64(math.Floor(math.Sqrt(float64(proof.B_A_Delta * proof.B_B_Delta))))
	if Delta_LPCheck != proof.Delta_LP {
		log.Println("[verifyRemoveLiquidityParams] invalid LP")
		return false, nil
	}
	// verify AMM info & DAO balance info
	l := ffmath.Multiply(big.NewInt(int64(proof.B_A_Delta)), big.NewInt(int64(proof.B_B_Delta)))
	r := ffmath.Multiply(big.NewInt(int64(proof.Delta_LP)), big.NewInt(int64(proof.Delta_LP)))
	if !ffmath.Equal(l, r) {
		log.Println("[verifyRemoveLiquidityParams] invalid delta amount")
		return false, nil
	}
	return true, nil
}

func (proof *RemoveLiquidityProof) addDaoInfo(b_Dao_A, b_Dao_B uint64, r_Dao_A, r_Dao_B *big.Int) {
	var (
		err error
	)
	if !validUint64(b_Dao_A) || !validUint64(b_Dao_B) {
		log.Println("[addDaoInfo] invalid params")
		return
	}
	proof.B_Dao_A = b_Dao_A
	proof.B_Dao_B = b_Dao_B
	proof.R_DaoA = r_Dao_A
	proof.R_DaoB = r_Dao_B
	proof.LC_Dao_A, err = twistedElgamal.Enc(big.NewInt(int64(b_Dao_A)), r_Dao_A, proof.Pk_Dao)
	if err != nil {
		log.Println("[RemoveLiquidityProof addDaoInfo] unable to encrypt:", err)
		return
	}
	proof.LC_Dao_B, err = twistedElgamal.Enc(big.NewInt(int64(b_Dao_B)), r_Dao_B, proof.Pk_Dao)
	if err != nil {
		log.Println("[RemoveLiquidityProof addDaoInfo] unable to encrypt:", err)
		return
	}
	// TODO re-implement P = \sqrt{x}/\sqrt{y}
	proof.P = uint64(math.Sqrt(float64(b_Dao_A)/float64(b_Dao_B)) * OneMillion)
}
