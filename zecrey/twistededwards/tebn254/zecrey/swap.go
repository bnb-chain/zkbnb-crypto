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

func ProveSwap(relation *SwapProofRelation) (proof *SwapProof, err error) {
	// check params
	if relation == nil {
		return nil, errors.New("[ProveSwap] invalid relation params")
	}
	var (
		alpha_sk_u, alpha_sk_uInv, alpha_bar_r_A *big.Int
		A_pk_u, A_T_uAC_uARPrimeInv              *Point
		c                                        *big.Int
		Z_sk_u, Z_bar_r_A, Z_sk_uInv             *big.Int
		buf                                      bytes.Buffer
		// gas part
		A_T_feeC_feeRPrimeInv *Point
		Z_bar_r_fee           *big.Int
		C_feeLPrimeInv        *Point
		alpha_bar_r_fee       *big.Int
	)
	// challenge buf
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writePointIntoBuf(&buf, relation.Pk_u)
	writePointIntoBuf(&buf, relation.Pk_pool)
	writeEncIntoBuf(&buf, relation.C_uA)
	writeEncIntoBuf(&buf, relation.C_uA_Delta)
	writePointIntoBuf(&buf, relation.T_uA)
	writeUint64IntoBuf(&buf, relation.B_A_Delta)
	writeUint64IntoBuf(&buf, relation.B_B_Delta)
	writeUint64IntoBuf(&buf, relation.B_treasuryfee_Delta)
	// ownership
	alpha_sk_u = curve.RandomValue()
	alpha_sk_uInv = ffmath.ModInverse(alpha_sk_u, Order)
	alpha_bar_r_A = curve.RandomValue()
	A_pk_u = curve.ScalarMul(G, alpha_sk_u)
	// user asset A part
	A_T_uAC_uARPrimeInv = curve.Add(
		relation.C_uA.CL,
		relation.C_uA_Delta.CL,
	)
	A_T_uAC_uARPrimeInv = curve.Neg(A_T_uAC_uARPrimeInv)
	A_T_uAC_uARPrimeInv = curve.ScalarMul(A_T_uAC_uARPrimeInv, alpha_sk_uInv)
	A_T_uAC_uARPrimeInv = curve.Add(A_T_uAC_uARPrimeInv, curve.ScalarMul(G, alpha_bar_r_A))
	if relation.GasFeeAssetId == relation.AssetAId {
		// gas part
		alpha_bar_r_fee = new(big.Int).Set(alpha_bar_r_A)
		A_T_feeC_feeRPrimeInv = new(Point).Set(A_T_uAC_uARPrimeInv)
	} else {
		// gas part
		C_feeLPrimeInv = curve.Neg(relation.C_fee.CL)
		alpha_bar_r_fee = curve.RandomValue()
		A_T_feeC_feeRPrimeInv = curve.Add(curve.ScalarMul(G, alpha_bar_r_fee), curve.ScalarMul(C_feeLPrimeInv, alpha_sk_uInv))
	}
	// gas fee
	writePointIntoBuf(&buf, A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&buf, relation.C_fee)
	writeUint64IntoBuf(&buf, uint64(relation.GasFeeAssetId))
	writeUint64IntoBuf(&buf, relation.GasFee)
	// write into buf
	writePointIntoBuf(&buf, A_pk_u)
	writePointIntoBuf(&buf, A_T_uAC_uARPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// compute response values
	Z_sk_u = ffmath.AddMod(alpha_sk_u, ffmath.Multiply(c, relation.Sk_u), Order)
	// construct responses
	Z_bar_r_A = ffmath.AddMod(alpha_bar_r_A, ffmath.Multiply(c, relation.Bar_r_A), Order)
	Z_sk_uInv = ffmath.AddMod(alpha_sk_uInv, ffmath.Multiply(c, ffmath.ModInverse(relation.Sk_u, Order)), Order)
	// gas fee
	Z_bar_r_fee = ffmath.AddMod(alpha_bar_r_fee, ffmath.Multiply(c, relation.Bar_r_fee), Order)
	// construct proof
	proof = &SwapProof{
		A_pk_u:                A_pk_u,
		A_T_uAC_uARPrimeInv:   A_T_uAC_uARPrimeInv,
		Z_sk_u:                Z_sk_u,
		Z_bar_r_A:             Z_bar_r_A,
		Z_sk_uInv:             Z_sk_uInv,
		ARangeProof:           relation.ARangeProof,
		C_uA:                  relation.C_uA,
		C_treasuryfee_Delta:   relation.C_treasuryfee_Delta,
		C_uA_Delta:            relation.C_uA_Delta,
		C_uB_Delta:            relation.C_uB_Delta,
		LC_poolA_Delta:        relation.LC_poolA_Delta,
		LC_poolB_Delta:        relation.LC_poolB_Delta,
		Pk_pool:               relation.Pk_pool,
		Pk_u:                  relation.Pk_u,
		Pk_treasury:           relation.Pk_treasury,
		R_DeltaA:              relation.R_DeltaA,
		R_DeltaB:              relation.R_DeltaB,
		R_Deltafee:            relation.R_Deltafee,
		T_uA:                  relation.T_uA,
		B_A_Delta:             relation.B_A_Delta,
		B_B_Delta:             relation.B_B_Delta,
		B_treasuryfee_Delta:   relation.B_treasuryfee_Delta,
		B_poolA:               relation.B_poolA,
		B_poolB:               relation.B_poolB,
		Alpha:                 relation.Alpha,
		Gamma:                 relation.Gamma,
		AssetAId:              relation.AssetAId,
		AssetBId:              relation.AssetBId,
		A_T_feeC_feeRPrimeInv: A_T_feeC_feeRPrimeInv,
		Z_bar_r_fee:           Z_bar_r_fee,
		C_fee:                 relation.C_fee,
		T_fee:                 relation.T_fee,
		GasFeeAssetId:         relation.GasFeeAssetId,
		GasFee:                relation.GasFee,
		GasFeePrimeRangeProof: relation.GasFeePrimeRangeProof,
	}
	return proof, nil
}

func (proof *SwapProof) Verify() (res bool, err error) {
	if !proof.ARangeProof.A.Equal(proof.T_uA) || !proof.GasFeePrimeRangeProof.A.Equal(proof.T_fee) || proof.Alpha != proof.B_A_Delta*OneMillion/proof.B_poolA {
		log.Println("[Verify SwapProof] invalid params")
		return false, errors.New("[Verify SwapProof] invalid params")
	}
	var (
		C_uAPrime    *ElGamalEnc
		C_uAPrimeNeg *ElGamalEnc
		c            *big.Int
		buf          bytes.Buffer
	)
	// challenge buf
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writePointIntoBuf(&buf, proof.Pk_u)
	writePointIntoBuf(&buf, proof.Pk_pool)
	writeEncIntoBuf(&buf, proof.C_uA)
	writeEncIntoBuf(&buf, proof.C_uA_Delta)
	writePointIntoBuf(&buf, proof.T_uA)
	writeUint64IntoBuf(&buf, proof.B_A_Delta)
	writeUint64IntoBuf(&buf, proof.B_B_Delta)
	writeUint64IntoBuf(&buf, proof.B_treasuryfee_Delta)
	// write into buf
	// gas fee
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writePointIntoBuf(&buf, proof.A_pk_u)
	writePointIntoBuf(&buf, proof.A_T_uAC_uARPrimeInv)
	// compute challenge
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// verify params
	isValidParams, err := verifySwapParams(proof)
	if err != nil {
		return false, err
	}
	if !isValidParams {
		return false, errors.New("[Verify SwapProof] invalid params")
	}
	// verify ownership
	l2 := curve.ScalarMul(G, proof.Z_sk_u)
	r2 := curve.Add(proof.A_pk_u, curve.ScalarMul(proof.Pk_u, c))
	if !l2.Equal(r2) {
		log.Println("[Verify SwapProof] l2 != r2")
		return false, nil
	}
	// A & gas fee proof
	if proof.GasFeeAssetId == proof.AssetAId {
		if !equalEnc(proof.C_uA, proof.C_fee) || !proof.A_T_uAC_uARPrimeInv.Equal(proof.A_T_feeC_feeRPrimeInv) {
			log.Println("[Verify SwapProof] invalid params")
			return false, errors.New("[Verify SwapProof] invalid params")
		}
		C_uAPrime, err = twistedElgamal.EncAdd(proof.C_uA, proof.C_uA_Delta)
		if err != nil {
			return false, err
		}
		C_uAPrime.CR = curve.Add(C_uAPrime.CR, curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee))))
		C_uAPrimeNeg = negElgamal(C_uAPrime)
		l3 := curve.Add(
			curve.ScalarMul(G, proof.Z_bar_r_A),
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
			log.Println("[Verify SwapProof] l3 != r3")
			return false, nil
		}
		// fee part
		C_feePrimeNeg := &ElGamalEnc{
			CL: new(Point).Set(C_uAPrimeNeg.CL),
			CR: new(Point).Set(C_uAPrimeNeg.CR),
		}
		l4 := curve.Add(
			curve.ScalarMul(G, proof.Z_bar_r_fee),
			curve.ScalarMul(C_feePrimeNeg.CL, proof.Z_sk_uInv),
		)
		r4 := curve.Add(
			proof.A_T_feeC_feeRPrimeInv,
			curve.ScalarMul(
				curve.Add(
					proof.T_fee,
					C_feePrimeNeg.CR,
				),
				c,
			),
		)
		if !l4.Equal(r4) {
			log.Println("[Verify SwapProof] l4 != r4")
			return false, nil
		}
	} else {
		C_uAPrime, err = twistedElgamal.EncAdd(proof.C_uA, proof.C_uA_Delta)
		if err != nil {
			return false, err
		}
		C_uAPrimeNeg = negElgamal(C_uAPrime)
		l3 := curve.Add(
			curve.ScalarMul(G, proof.Z_bar_r_A),
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
			log.Println("[Verify SwapProof] l3 != r3")
			return false, nil
		}
		// fee part
		C_feeRPrime := curve.Add(proof.C_fee.CR, curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee))))
		C_feePrime := &ElGamalEnc{
			CL: proof.C_fee.CL,
			CR: C_feeRPrime,
		}
		if err != nil {
			return false, err
		}
		C_feePrimeNeg := negElgamal(C_feePrime)
		l4 := curve.Add(
			curve.ScalarMul(G, proof.Z_bar_r_fee),
			curve.ScalarMul(C_feePrimeNeg.CL, proof.Z_sk_uInv),
		)
		r4 := curve.Add(
			proof.A_T_feeC_feeRPrimeInv,
			curve.ScalarMul(
				curve.Add(
					proof.T_fee,
					C_feePrimeNeg.CR,
				),
				c,
			),
		)
		if !l4.Equal(r4) {
			log.Println("[Verify SwapProof] l4 != r4")
			return false, nil
		}
	}

	var (
		swapRangeProofCount = 2
		rangeChan           = make(chan int, swapRangeProofCount)
	)
	go verifyCtRangeRoutine(proof.ARangeProof, rangeChan)
	go verifyCtRangeRoutine(proof.GasFeePrimeRangeProof, rangeChan)
	for i := 0; i < swapRangeProofCount; i++ {
		val := <-rangeChan
		if val == ErrCode {
			log.Println("[Verify SwapProof] invalid range proof")
			return false, nil
		}
	}
	return true, nil
}

func verifySwapParams(proof *SwapProof) (res bool, err error) {
	// pk^r
	CL1 := curve.ScalarMul(proof.Pk_u, proof.R_DeltaA)
	// g^r h^b
	hb1 := curve.ScalarMul(H, big.NewInt(int64(proof.B_A_Delta)))
	B_poolA_Delta := proof.B_A_Delta - proof.B_treasuryfee_Delta
	hbpool := curve.ScalarMul(H, big.NewInt(int64(B_poolA_Delta)))
	gr1 := curve.ScalarBaseMul(proof.R_DeltaA)
	C_uA_Delta := &ElGamalEnc{
		CL: CL1,
		CR: curve.Add(gr1, curve.Neg(hb1)),
	}
	// pk^r
	CL2 := curve.ScalarMul(proof.Pk_u, proof.R_DeltaB)
	// g^r h^b
	hb2 := curve.ScalarMul(H, big.NewInt(int64(proof.B_B_Delta)))
	gr2 := curve.ScalarBaseMul(proof.R_DeltaB)
	C_uB_Delta := &ElGamalEnc{
		CL: CL2,
		CR: curve.Add(gr2, hb2),
	}
	LC_poolA_Delta := &ElGamalEnc{
		CL: curve.ScalarMul(proof.Pk_pool, proof.R_DeltaA),
		CR: curve.Add(gr1, hbpool),
	}
	LC_poolB_Delta := &ElGamalEnc{
		CL: curve.ScalarMul(proof.Pk_pool, proof.R_DeltaB),
		CR: curve.Add(gr2, curve.Neg(hb2)),
	}
	if !equalEnc(C_uA_Delta, proof.C_uA_Delta) || !equalEnc(C_uB_Delta, proof.C_uB_Delta) ||
		!equalEnc(LC_poolA_Delta, proof.LC_poolA_Delta) || !equalEnc(LC_poolB_Delta, proof.LC_poolB_Delta) {
		return false, nil
	}
	// TODO verify AMM info & DAO balance info
	if proof.B_poolB < proof.B_B_Delta {
		log.Println("[verifySwapParams] invalid balance")
		return false, nil
	}
	//alphaGamma := ffmath.Multiply(big.NewInt(int64(proof.Alpha)), big.NewInt(int64(proof.Gamma)))
	//deltaBCheck := ffmath.Multiply(
	//	alphaGamma,
	//	big.NewInt(int64(proof.B_poolB)))
	//deltaBCheck = ffmath.Div(deltaBCheck, ffmath.Add(big.NewInt(int64(OneMillion*TenThousand)), alphaGamma))
	//if deltaBCheck.Cmp(big.NewInt(int64(proof.B_B_Delta))) < 0 {
	//	return false, nil
	//}
	k := ffmath.Multiply(big.NewInt(int64(proof.B_poolA)), big.NewInt(int64(proof.B_poolB)))
	poolADelta := proof.B_A_Delta - proof.B_treasuryfee_Delta
	kPrime := ffmath.Multiply(big.NewInt(int64(proof.B_poolA+poolADelta)), big.NewInt(int64(proof.B_poolB-proof.B_B_Delta)))
	if kPrime.Cmp(k) < 0 {
		log.Println("[verifySwapParams] invalid k")
		return false, nil
	}
	return true, nil
}

func (proof *SwapProof) AddDaoInfo(b_poolA, b_poolB uint64) {
	// set params
	proof.B_poolA = b_poolA
	proof.B_poolB = b_poolB
	proof.Alpha = proof.B_A_Delta * OneMillion / proof.B_poolA
}
