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
		Z_rDelta_LP                               *big.Int
		Z_sk_u, Z_bar_r_LP, Z_sk_uInv             *big.Int
		buf                                       bytes.Buffer
		// gas fee
		A_T_feeDivC_feeRprime *Point
		Z_bar_r_fee           *big.Int
		C_feeLPrimeInv        *Point
		alpha_bar_r_fee       *big.Int
	)
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writePointIntoBuf(&buf, relation.Pk_u)
	writeEncIntoBuf(&buf, relation.C_u_LP)
	writeEncIntoBuf(&buf, relation.C_u_LP_Delta)
	writePointIntoBuf(&buf, relation.T_uLP)
	// valid enc
	alpha_r_DeltaLP = curve.RandomValue()
	A_CLPL_Delta = curve.ScalarMul(relation.Pk_u, alpha_r_DeltaLP)
	A_CLPR_DeltaHExp_DeltaLPNeg = curve.ScalarMul(G, alpha_r_DeltaLP)
	// write into buf
	writePointIntoBuf(&buf, A_CLPL_Delta)
	writePointIntoBuf(&buf, A_CLPR_DeltaHExp_DeltaLPNeg)
	// ownership
	alpha_sk_u = curve.RandomValue()
	alpha_sk_uInv = ffmath.ModInverse(alpha_sk_u, Order)
	alpha_bar_r_LP = curve.RandomValue()
	A_pk_u = curve.ScalarMul(G, alpha_sk_u)
	// user asset A part
	A_T_uLPC_uLPRPrimeInv = curve.Add(
		relation.C_u_LP.CL,
		relation.C_u_LP_Delta.CL,
	)
	A_T_uLPC_uLPRPrimeInv = curve.Neg(A_T_uLPC_uLPRPrimeInv)
	A_T_uLPC_uLPRPrimeInv = curve.ScalarMul(A_T_uLPC_uLPRPrimeInv, alpha_sk_uInv)
	A_T_uLPC_uLPRPrimeInv = curve.Add(
		A_T_uLPC_uLPRPrimeInv,
		curve.ScalarMul(G, alpha_bar_r_LP))
	// write into buf
	writePointIntoBuf(&buf, A_pk_u)
	writePointIntoBuf(&buf, A_T_uLPC_uLPRPrimeInv)
	// gas fee
	C_feeLPrimeInv = curve.Neg(relation.C_fee.CL)
	alpha_bar_r_fee = curve.RandomValue()
	A_T_feeDivC_feeRprime = curve.Add(curve.ScalarMul(G, alpha_bar_r_fee), curve.ScalarMul(C_feeLPrimeInv, alpha_sk_uInv))
	// gas fee
	writePointIntoBuf(&buf, A_T_feeDivC_feeRprime)
	writeEncIntoBuf(&buf, relation.C_fee)
	writeUint64IntoBuf(&buf, uint64(relation.GasFeeAssetId))
	writeUint64IntoBuf(&buf, relation.GasFee)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// compute response values
	Z_rDelta_LP = ffmath.AddMod(alpha_r_DeltaLP, ffmath.Multiply(c, relation.R_DeltaLP), Order)
	Z_sk_u = ffmath.AddMod(alpha_sk_u, ffmath.Multiply(c, relation.Sk_u), Order)
	Z_bar_r_LP = ffmath.AddMod(alpha_bar_r_LP, ffmath.Multiply(c, relation.Bar_r_LP), Order)
	Z_sk_uInv = ffmath.AddMod(alpha_sk_uInv, ffmath.Multiply(c, ffmath.ModInverse(relation.Sk_u, Order)), Order)
	// gas fee
	Z_bar_r_fee = ffmath.AddMod(alpha_bar_r_fee, ffmath.Multiply(c, relation.Bar_r_fee), Order)
	// construct proof
	proof = &RemoveLiquidityProof{
		A_CLPL_Delta:                A_CLPL_Delta,
		A_CLPR_DeltaHExp_DeltaLPNeg: A_CLPR_DeltaHExp_DeltaLPNeg,
		Z_rDelta_LP:                 Z_rDelta_LP,
		A_pk_u:                      A_pk_u,
		A_T_uLPC_uLPRPrimeInv:       A_T_uLPC_uLPRPrimeInv,
		Z_sk_u:                      Z_sk_u,
		Z_bar_r_LP:                  Z_bar_r_LP,
		Z_sk_uInv:                   Z_sk_uInv,
		LPRangeProof:                relation.LPRangeProof,
		LC_pool_A:                   relation.LC_pool_A,
		LC_pool_B:                   relation.LC_pool_B,
		C_uA_Delta:                  relation.C_uA_Delta,
		C_uB_Delta:                  relation.C_uB_Delta,
		LC_poolA_Delta:              relation.LC_poolA_Delta,
		LC_poolB_Delta:              relation.LC_poolB_Delta,
		C_u_LP:                      relation.C_u_LP,
		C_u_LP_Delta:                relation.C_u_LP_Delta,
		Pk_pool:                     relation.Pk_pool,
		Pk_u:                        relation.Pk_u,
		T_uLP:                       relation.T_uLP,
		R_poolA:                     relation.R_poolA,
		R_poolB:                     relation.R_poolB,
		R_DeltaA:                    relation.R_DeltaA,
		R_DeltaB:                    relation.R_DeltaB,
		B_pool_A:                    relation.B_pool_A,
		B_pool_B:                    relation.B_pool_B,
		B_A_Delta:                   relation.B_A_Delta,
		B_B_Delta:                   relation.B_B_Delta,
		MinB_A_Delta:                relation.MinB_A_Delta,
		MinB_B_Delta:                relation.MinB_B_Delta,
		Delta_LP:                    relation.Delta_LP,
		P:                           relation.P,
		AssetAId:                    relation.AssetAId,
		AssetBId:                    relation.AssetBId,
		A_T_feeC_feeRPrimeInv:       A_T_feeDivC_feeRprime,
		Z_bar_r_fee:                 Z_bar_r_fee,
		C_fee:                       relation.C_fee,
		T_fee:                       relation.T_fee,
		GasFeeAssetId:               relation.GasFeeAssetId,
		GasFee:                      relation.GasFee,
		GasFeePrimeRangeProof:       relation.GasFeePrimeRangeProof,
	}
	return proof, nil
}

func (proof *RemoveLiquidityProof) Verify() (res bool, err error) {
	if !proof.LPRangeProof.A.Equal(proof.T_uLP) {
		log.Println("[Verify RemoveLiquidity] invalid params")
		return false, errors.New("[Verify RemoveLiquidity] invalid params")
	}
	var (
		C_uLPPrime    *ElGamalEnc
		C_uLPPrimeNeg *ElGamalEnc
		c             *big.Int
		buf           bytes.Buffer
	)
	res, err = proof.LPRangeProof.Verify()
	if err != nil {
		log.Println("[Verify RemoveLiquidity] err range proof:", err)
		return false, err
	}
	if !res {
		log.Println("[Verify RemoveLiquidity] invalid range proof")
		return false, nil
	}
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writePointIntoBuf(&buf, proof.Pk_u)
	writeEncIntoBuf(&buf, proof.C_u_LP)
	writeEncIntoBuf(&buf, proof.C_u_LP_Delta)
	writePointIntoBuf(&buf, proof.T_uLP)
	// write into buf
	writePointIntoBuf(&buf, proof.A_CLPL_Delta)
	writePointIntoBuf(&buf, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&buf, proof.A_pk_u)
	writePointIntoBuf(&buf, proof.A_T_uLPC_uLPRPrimeInv)
	// gas fee
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify RemoveLiquidityProof] unable to compute challenge")
		return false, err
	}
	// verify params
	// verify params
	isValidParams, err := verifyRemoveLiquidityParams(proof)
	if err != nil {
		return false, err
	}
	if !isValidParams {
		return false, errors.New("[Verify RemoveLiquidityProof] invalid params")
	}
	// verify enc
	l1 := curve.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 := curve.Add(proof.A_CLPL_Delta, curve.ScalarMul(proof.C_u_LP_Delta.CL, c))
	if !l1.Equal(r1) {
		log.Println("[Verify RemoveLiquidityProof] l1 != r1")
		return false, nil
	}
	// verify ownership
	l2 := curve.ScalarMul(G, proof.Z_sk_u)
	r2 := curve.Add(proof.A_pk_u, curve.ScalarMul(proof.Pk_u, c))
	if !l2.Equal(r2) {
		log.Println("[Verify RemoveLiquidityProof] l2 != r2")
		return false, nil
	}
	C_uLPPrime, err = twistedElgamal.EncAdd(proof.C_u_LP, proof.C_u_LP_Delta)
	if err != nil {
		return false, err
	}
	C_uLPPrimeNeg = negElgamal(C_uLPPrime)
	l3 := curve.Add(
		curve.ScalarMul(G, proof.Z_bar_r_LP),
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
		log.Println("[Verify RemoveLiquidityProof] l3 != r3")
		return false, nil
	}
	// verify gas fee proof
	C_feeDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee)))
	C_feeLprimeInv := curve.Neg(proof.C_fee.CL)
	T_feeDivC_feeRprime := curve.Add(proof.T_fee, curve.Neg(curve.Add(proof.C_fee.CR, C_feeDelta)))
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l4 := curve.Add(curve.ScalarMul(G, proof.Z_bar_r_fee), curve.ScalarMul(C_feeLprimeInv, proof.Z_sk_uInv))
	r4 := curve.Add(proof.A_T_feeC_feeRPrimeInv, curve.ScalarMul(T_feeDivC_feeRprime, c))
	if !l4.Equal(r4) {
		log.Println("[Verify RemoveLiquidityProof] l4!=r4")
		return false, nil
	}
	return true, nil
}

func verifyRemoveLiquidityParams(proof *RemoveLiquidityProof) (res bool, err error) {
	C_uA_DeltaCL := curve.ScalarMul(proof.Pk_u, proof.R_DeltaA)
	C_uA_DeltaCRL := curve.ScalarBaseMul(proof.R_DeltaA)
	C_uA_DeltaCRR := curve.ScalarMul(H, big.NewInt(int64(proof.B_A_Delta)))
	C_uA_Delta := &ElGamalEnc{
		CL: C_uA_DeltaCL,
		CR: curve.Add(C_uA_DeltaCRL, C_uA_DeltaCRR),
	}
	C_uB_DeltaCL := curve.ScalarMul(proof.Pk_u, proof.R_DeltaB)
	C_uB_DeltaCRL := curve.ScalarBaseMul(proof.R_DeltaB)
	C_uB_DeltaCRR := curve.ScalarMul(H, big.NewInt(int64(proof.B_B_Delta)))
	C_uB_Delta := &ElGamalEnc{
		CL: C_uB_DeltaCL,
		CR: curve.Add(C_uB_DeltaCRL, C_uB_DeltaCRR),
	}
	LC_poolA_Delta := &ElGamalEnc{
		CL: curve.ScalarMul(proof.Pk_pool, proof.R_DeltaA),
		CR: curve.Add(C_uA_DeltaCRL, curve.Neg(C_uA_DeltaCRR)),
	}
	LC_poolB_Delta := &ElGamalEnc{
		CL: curve.ScalarMul(proof.Pk_pool, proof.R_DeltaB),
		CR: curve.Add(C_uB_DeltaCRL, curve.Neg(C_uB_DeltaCRR)),
	}
	if !equalEnc(C_uA_Delta, proof.C_uA_Delta) || !equalEnc(C_uB_Delta, proof.C_uB_Delta) ||
		!equalEnc(LC_poolA_Delta, proof.LC_poolA_Delta) || !equalEnc(LC_poolB_Delta, proof.LC_poolB_Delta) {
		log.Println("[verifyRemoveLiquidityParams] invalid balance enc")
		return false, nil
	}
	// verify AMM info & DAO balance info
	l := ffmath.Multiply(big.NewInt(int64(proof.B_A_Delta)), big.NewInt(int64(proof.B_B_Delta)))
	r := ffmath.Multiply(big.NewInt(int64(proof.Delta_LP)), big.NewInt(int64(proof.Delta_LP)))
	if l.Cmp(r) > 0 {
		log.Println("[verifyRemoveLiquidityParams] invalid delta amount")
		return false, nil
	}
	return true, nil
}

func (proof *RemoveLiquidityProof) AddPoolInfo(
	Pk_pool *Point,
	B_A_Delta, B_B_Delta uint64,
	b_pool_A, b_pool_B uint64, r_pool_A, r_pool_B *big.Int,
) (err error) {
	if B_A_Delta < proof.MinB_A_Delta || B_B_Delta < proof.MinB_B_Delta {
		return errors.New("[AddPoolInfo] invalid delta")
	}
	// set basic params
	proof.Pk_pool = Pk_pool
	proof.B_A_Delta = B_A_Delta
	proof.B_B_Delta = B_B_Delta
	proof.B_pool_A = b_pool_A
	proof.B_pool_B = b_pool_B
	proof.R_poolA = r_pool_A
	proof.R_poolB = r_pool_B
	proof.C_uA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), proof.R_DeltaA, proof.Pk_u)
	if err != nil {
		log.Println("[AddPoolInfo] err info:", err)
		return err
	}
	proof.C_uB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), proof.R_DeltaB, proof.Pk_u)
	if err != nil {
		log.Println("[AddPoolInfo] err info:", err)
		return err
	}
	proof.LC_pool_A, err = twistedElgamal.Enc(big.NewInt(int64(b_pool_A)), r_pool_A, Pk_pool)
	if err != nil {
		log.Println("[RemoveLiquidityProof AddPoolInfo] unable to encrypt:", err)
		return err
	}
	proof.LC_pool_B, err = twistedElgamal.Enc(big.NewInt(int64(b_pool_B)), r_pool_B, Pk_pool)
	if err != nil {
		log.Println("[RemoveLiquidityProof AddPoolInfo] unable to encrypt:", err)
		return err
	}
	// compute LC_poolj_Delta
	proof.LC_poolA_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(B_A_Delta)), proof.R_DeltaA, Pk_pool)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return err
	}
	proof.LC_poolB_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(B_B_Delta)), proof.R_DeltaB, Pk_pool)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return err
	}
	// TODO re-implement P = \sqrt{x}/\sqrt{y}
	proof.P = uint64(math.Sqrt(float64(b_pool_A)/float64(b_pool_B)) * OneMillion)
	return nil
}
