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

func ProveAddLiquidity(relation *AddLiquidityRelation) (proof *AddLiquidityProof, err error) {
	if relation == nil {
		log.Println("[ProveAddLiquidity] invalid params")
		return nil, errors.New("[ProveAddLiquidity] invalid params")
	}
	var (
		alpha_r_DeltaLP                                         *big.Int
		A_CLPL_Delta, A_CLPR_DeltaHExp_DeltaLPNeg               *Point
		alpha_sk_u, alpha_sk_uInv, alpha_bar_r_A, alpha_bar_r_B *big.Int
		A_pk_u, A_T_uAC_uARPrimeInv, A_T_uBC_uBRPrimeInv        *Point
		c                                                       *big.Int
		Z_rDeltaLP                                              *big.Int
		Z_sk_u, Z_bar_r_A, Z_bar_r_B, Z_sk_uInv                 *big.Int
		buf                                                     bytes.Buffer
	)
	writePointIntoBuf(&buf, relation.G)
	writePointIntoBuf(&buf, relation.H)
	writePointIntoBuf(&buf, relation.Pk_u)
	writePointIntoBuf(&buf, relation.Pk_Dao)
	writeEncIntoBuf(&buf, relation.C_uA)
	writeEncIntoBuf(&buf, relation.C_uB)
	writeEncIntoBuf(&buf, relation.C_uA_Delta)
	writeEncIntoBuf(&buf, relation.C_uB_Delta)
	writeEncIntoBuf(&buf, relation.C_LP_Delta)
	writePointIntoBuf(&buf, relation.T_uA)
	writePointIntoBuf(&buf, relation.T_uB)
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
	alpha_bar_r_A = curve.RandomValue()
	alpha_bar_r_B = curve.RandomValue()
	A_pk_u = curve.ScalarMul(relation.G, alpha_sk_u)
	// user asset A part
	A_T_uAC_uARPrimeInv = curve.Add(
		relation.C_uA.CL,
		curve.Neg(relation.C_uA_Delta.CL),
	)
	A_T_uAC_uARPrimeInv = curve.Neg(A_T_uAC_uARPrimeInv)
	A_T_uAC_uARPrimeInv = curve.ScalarMul(A_T_uAC_uARPrimeInv, alpha_sk_uInv)
	A_T_uAC_uARPrimeInv = curve.Add(
		A_T_uAC_uARPrimeInv,
		curve.ScalarMul(relation.G, alpha_bar_r_A))
	// user asset B part
	A_T_uBC_uBRPrimeInv = curve.Add(
		relation.C_uB.CL,
		curve.Neg(relation.C_uB_Delta.CL),
	)
	A_T_uBC_uBRPrimeInv = curve.Neg(A_T_uBC_uBRPrimeInv)
	A_T_uBC_uBRPrimeInv = curve.ScalarMul(A_T_uBC_uBRPrimeInv, alpha_sk_uInv)
	A_T_uBC_uBRPrimeInv = curve.Add(A_T_uBC_uBRPrimeInv, curve.ScalarMul(relation.G, alpha_bar_r_B))
	// write into buf
	writePointIntoBuf(&buf, A_pk_u)
	writePointIntoBuf(&buf, A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&buf, A_T_uBC_uBRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// compute response values
	Z_rDeltaLP = ffmath.AddMod(alpha_r_DeltaLP, ffmath.Multiply(c, relation.R_DeltaLP), Order)
	Z_sk_u = ffmath.AddMod(alpha_sk_u, ffmath.Multiply(c, relation.Sk_u), Order)
	Z_bar_r_A = ffmath.AddMod(alpha_bar_r_A, ffmath.Multiply(c, relation.Bar_r_A), Order)
	Z_bar_r_B = ffmath.AddMod(alpha_bar_r_B, ffmath.Multiply(c, relation.Bar_r_B), Order)
	Z_sk_uInv = ffmath.AddMod(alpha_sk_uInv, ffmath.Multiply(c, ffmath.ModInverse(relation.Sk_u, Order)), Order)
	// constrcut proof
	proof = &AddLiquidityProof{
		A_CLPL_Delta:                A_CLPL_Delta,
		A_CLPR_DeltaHExp_DeltaLPNeg: A_CLPR_DeltaHExp_DeltaLPNeg,
		Z_rDelta_LP:                 Z_rDeltaLP,
		A_pk_u:                      A_pk_u,
		A_T_uAC_uARPrimeInv:         A_T_uAC_uARPrimeInv,
		A_T_uBC_uBRPrimeInv:         A_T_uBC_uBRPrimeInv,
		Z_sk_u:                      Z_sk_u,
		Z_bar_r_A:                   Z_bar_r_A,
		Z_bar_r_B:                   Z_bar_r_B,
		Z_sk_uInv:                   Z_sk_uInv,
		ARangeProof:                 relation.ARangeProof,
		BRangeProof:                 relation.BRangeProof,
		C_uA:                        relation.C_uA,
		C_uB:                        relation.C_uB,
		C_uA_Delta:                  relation.C_uA_Delta,
		C_uB_Delta:                  relation.C_uB_Delta,
		LC_DaoA_Delta:               relation.LC_DaoA_Delta,
		LC_DaoB_Delta:               relation.LC_DaoB_Delta,
		C_LP_Delta:                  relation.C_LP_Delta,
		Pk_u:                        relation.Pk_u,
		Pk_Dao:                      relation.Pk_Dao,
		R_DeltaA:                    relation.R_DeltaA,
		R_DeltaB:                    relation.R_DeltaB,
		T_uA:                        relation.T_uA,
		T_uB:                        relation.T_uB,
		B_DaoA:                      0,
		B_DaoB:                      0,
		B_A_Delta:                   relation.B_A_Delta,
		B_B_Delta:                   relation.B_B_Delta,
		Delta_LP:                    relation.Delta_LP,
		G:                           relation.G,
		H:                           relation.H,
	}
	return proof, nil
}

func (proof *AddLiquidityProof) Verify() (res bool, err error) {
	// verify range proofs
	if !proof.ARangeProof.A.Equal(proof.T_uA) || !proof.BRangeProof.A.Equal(proof.T_uB) {
		log.Println("[Verify AddLiquidityProof] invalid params")
		return false, errors.New("[Verify AddLiquidityProof] invalid params")
	}
	var (
		C_uAPrime, C_uBPrime       *ElGamalEnc
		C_uAPrimeNeg, C_uBPrimeNeg *ElGamalEnc
		c                          *big.Int
		buf                        bytes.Buffer
		rangeChan                  = make(chan int, addLiquidityRangeProofCount)
	)
	go verifyCtRangeRoutine(proof.ARangeProof, rangeChan)
	go verifyCtRangeRoutine(proof.BRangeProof, rangeChan)
	// challenge buf
	writePointIntoBuf(&buf, proof.G)
	writePointIntoBuf(&buf, proof.H)
	writePointIntoBuf(&buf, proof.Pk_u)
	writePointIntoBuf(&buf, proof.Pk_Dao)
	writeEncIntoBuf(&buf, proof.C_uA)
	writeEncIntoBuf(&buf, proof.C_uB)
	writeEncIntoBuf(&buf, proof.C_uA_Delta)
	writeEncIntoBuf(&buf, proof.C_uB_Delta)
	writeEncIntoBuf(&buf, proof.C_LP_Delta)
	writePointIntoBuf(&buf, proof.T_uA)
	writePointIntoBuf(&buf, proof.T_uB)
	// write into buf
	writePointIntoBuf(&buf, proof.A_CLPL_Delta)
	writePointIntoBuf(&buf, proof.A_CLPR_DeltaHExp_DeltaLPNeg)
	// write into buf
	writePointIntoBuf(&buf, proof.A_pk_u)
	writePointIntoBuf(&buf, proof.A_T_uAC_uARPrimeInv)
	writePointIntoBuf(&buf, proof.A_T_uBC_uBRPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify AddLiquidityProof] unable to compute challenge")
		return false, err
	}
	// verify params
	isValidParams, err := verifyAddLiquidityParams(proof)
	if err != nil {
		return false, err
	}
	if !isValidParams {
		return false, errors.New("[Verify AddLiquidityProof] invalid params")
	}
	// verify enc
	l1 := curve.ScalarMul(proof.Pk_u, proof.Z_rDelta_LP)
	r1 := curve.Add(proof.A_CLPL_Delta, curve.ScalarMul(proof.C_LP_Delta.CL, c))
	if !l1.Equal(r1) {
		log.Println("[Verify AddLiquidityProof] l1 != r1")
		return false, nil
	}
	// verify ownership
	l2 := curve.ScalarMul(proof.G, proof.Z_sk_u)
	r2 := curve.Add(proof.A_pk_u, curve.ScalarMul(proof.Pk_u, c))
	if !l2.Equal(r2) {
		log.Println("[Verify AddLiquidityProof] l2 != r2")
		return false, nil
	}
	C_uAPrime, err = twistedElgamal.EncSub(proof.C_uA, proof.C_uA_Delta)
	if err != nil {
		return false, err
	}
	C_uBPrime, err = twistedElgamal.EncSub(proof.C_uB, proof.C_uB_Delta)
	if err != nil {
		return false, err
	}
	C_uAPrimeNeg = negElgamal(C_uAPrime)
	C_uBPrimeNeg = negElgamal(C_uBPrime)
	l3 := curve.Add(
		curve.ScalarMul(proof.G, proof.Z_bar_r_A),
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
		log.Println("[Verify AddLiquidityProof] l3 != r3")
		return false, nil
	}
	l4 := curve.Add(
		curve.ScalarMul(proof.G, proof.Z_bar_r_B),
		curve.ScalarMul(C_uBPrimeNeg.CL, proof.Z_sk_uInv),
	)
	r4 := curve.Add(
		proof.A_T_uBC_uBRPrimeInv,
		curve.ScalarMul(
			curve.Add(
				proof.T_uB,
				C_uBPrimeNeg.CR,
			),
			c,
		),
	)
	if !l4.Equal(r4) {
		log.Println("[Verify AddLiquidityProof] l4 != r4")
		return false, nil
	}
	for i := 0; i < addLiquidityRangeProofCount; i++ {
		val := <-rangeChan
		if val == ErrCode {
			log.Println("[Verify AddLiquidityProof] invalid range proof")
			return false, nil
		}
	}
	return true, nil
}

func verifyAddLiquidityParams(proof *AddLiquidityProof) (res bool, err error) {
	if !proof.G.Equal(G) || !proof.H.Equal(H) {
		log.Println("[verifyAddLiquidityParams] invalid params")
		return false, errors.New("[verifyAddLiquidityParams] invalid params")
	}
	// check uint64 & int64
	if !validUint64(proof.B_A_Delta) || !validUint64(proof.B_B_Delta) ||
		!validUint64(proof.B_DaoA) || !validUint64(proof.B_DaoB) {
		log.Println("[verifyAddLiquidityParams] invalid params")
		return false, errors.New("[verifyAddLiquidityParams] invalid params")
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
		log.Println("[verifyAddLiquidityParams] invalid balance enc")
		return false, nil
	}
	// verify LP
	Delta_LPCheck := uint64(math.Floor(math.Sqrt(float64(proof.B_A_Delta * proof.B_B_Delta))))
	if Delta_LPCheck != proof.Delta_LP {
		log.Println("[verifyAddLiquidityParams] invalid LP")
		return false, nil
	}
	// verify AMM info & DAO balance info
	if ffmath.Multiply(big.NewInt(int64(proof.B_DaoB)), big.NewInt(int64(proof.B_A_Delta))).Cmp(
		ffmath.Multiply(big.NewInt(int64(proof.B_DaoA)), big.NewInt(int64(proof.B_B_Delta)))) != 0 {
		log.Println("[verifyAddLiquidityParams] invalid liquidity rate")
		return false, nil
	}
	return true, nil
}

func (proof *AddLiquidityProof) AddDaoInfo(b_Dao_A, b_Dao_B uint64) {
	if !validUint64(b_Dao_A) || !validUint64(b_Dao_B) {
		log.Println("[AddDaoInfo] invalid params")
		return
	}
	proof.B_DaoA = b_Dao_A
	proof.B_DaoB = b_Dao_B
}
