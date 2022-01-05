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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/util"
)

const (
	withdrawRangeProofCount = 2
)

func ProveWithdraw(relation *WithdrawProofRelation) (proof *WithdrawProof, err error) {
	if relation == nil {
		log.Println("[ProveWithdraw] invalid params")
		return nil, ErrInvalidParams
	}
	var (
		alpha_rbar, alpha_r_feebar, alpha_sk, alpha_skInv *big.Int
		A_pk, A_TDivCRprime, A_T_feeDivC_feeRprime        *Point
		CLPrimeInv, C_feeLPrimeInv                        *Point
		buf                                               bytes.Buffer
		z_bar_r, z_bar_r_fee, z_sk, z_skInv               *big.Int
	)
	// balance part
	CLPrimeInv = curve.Neg(relation.C.CL)
	alpha_rbar, alpha_sk, alpha_skInv,
		A_pk, A_TDivCRprime = commitBalance(G, CLPrimeInv)
	// if gas fee asset id == asset id
	if relation.GasFeeAssetId == relation.AssetId {
		// fee part same as balance part
		C_feeLPrimeInv = new(Point).Set(CLPrimeInv)
		alpha_r_feebar = new(big.Int).Set(alpha_rbar)
		A_T_feeDivC_feeRprime = new(Point).Set(A_TDivCRprime)
	} else {
		// fee part
		C_feeLPrimeInv = curve.Neg(relation.C_fee.CL)
		alpha_r_feebar = curve.RandomValue()
		A_T_feeDivC_feeRprime = curve.Add(curve.ScalarMul(G, alpha_r_feebar), curve.ScalarMul(C_feeLPrimeInv, alpha_skInv))
	}
	// write common inputs into buf
	// then generate the challenge c
	buf.Write(PaddingBigIntBytes(FixedCurve))
	buf.Write(PaddingBigIntBytes(relation.ReceiveAddr))
	// gas fee
	writeEncIntoBuf(&buf, relation.C_fee)
	writeUint64IntoBuf(&buf, uint64(relation.GasFeeAssetId))
	writeUint64IntoBuf(&buf, relation.GasFee)
	writeUint64IntoBuf(&buf, uint64(relation.AssetId))
	writeUint64IntoBuf(&buf, uint64(relation.ChainId))
	writeEncIntoBuf(&buf, relation.C)
	writePointIntoBuf(&buf, relation.T)
	writePointIntoBuf(&buf, relation.T_fee)
	writePointIntoBuf(&buf, relation.Pk)
	writePointIntoBuf(&buf, A_pk)
	writePointIntoBuf(&buf, A_TDivCRprime)
	writePointIntoBuf(&buf, A_T_feeDivC_feeRprime)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	z_bar_r, z_sk, z_skInv = respondBalance(relation.Bar_r, relation.Sk, alpha_rbar, alpha_sk, alpha_skInv, c)
	z_bar_r_fee = ffmath.AddMod(alpha_r_feebar, ffmath.Multiply(c, relation.R_feeBar), Order)
	proof = &WithdrawProof{
		A_pk:                  A_pk,
		A_TDivCRprime:         A_TDivCRprime,
		A_T_feeC_feeRPrimeInv: A_T_feeDivC_feeRprime,
		Z_bar_r:               z_bar_r,
		Z_bar_r_fee:           z_bar_r_fee,
		Z_sk:                  z_sk,
		Z_skInv:               z_skInv,
		BPrimeRangeProof:      relation.BPrimeRangeProof,
		GasFeePrimeRangeProof: relation.GasFeePrimeRangeProof,
		BStar:                 relation.Bstar,
		C:                     relation.C,
		T:                     relation.T,
		Pk:                    relation.Pk,
		ReceiveAddr:           relation.ReceiveAddr,
		AssetId:               relation.AssetId,
		ChainId:               relation.ChainId,
		C_fee:                 relation.C_fee,
		T_fee:                 relation.T_fee,
		GasFeeAssetId:         relation.GasFeeAssetId,
		GasFee:                relation.GasFee,
	}
	return proof, nil
}

func (proof *WithdrawProof) Verify() (bool, error) {
	if !validUint64(proof.BStar) || !validUint64(proof.GasFee) {
		log.Println("[Verify WithdrawProof] invalid params")
		return false, errors.New("[Verify WithdrawProof] invalid params")
	}
	// generate the challenge
	var (
		CLprimeInv, C_feeLprimeInv, TDivCRprime, T_feeDivC_feeRprime *Point
		buf                                                          bytes.Buffer
		rangeChan                                                    = make(chan int, 2)
	)
	// check params
	if proof.GasFeeAssetId == proof.AssetId {
		if !equalEnc(proof.C, proof.C_fee) || !proof.A_TDivCRprime.Equal(proof.A_T_feeC_feeRPrimeInv) {
			log.Println("[Verify WithdrawProof] invalid params")
			return false, errors.New("[Verify WithdrawProof] invalid params")
		}
		CRDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.BStar+proof.GasFee)))
		CLprimeInv = curve.Neg(proof.C.CL)
		TDivCRprime = curve.Add(proof.T, curve.Neg(curve.Add(proof.C.CR, CRDelta)))
		C_feeLprimeInv = new(Point).Set(CLprimeInv)
		T_feeDivC_feeRprime = new(Point).Set(TDivCRprime)
	} else {
		CRDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.BStar)))
		C_feeDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee)))
		CLprimeInv = curve.Neg(proof.C.CL)
		TDivCRprime = curve.Add(proof.T, curve.Neg(curve.Add(proof.C.CR, CRDelta)))
		C_feeLprimeInv = curve.Neg(proof.C_fee.CL)
		T_feeDivC_feeRprime = curve.Add(proof.T_fee, curve.Neg(curve.Add(proof.C_fee.CR, C_feeDelta)))
	}
	// check range params
	if !proof.BPrimeRangeProof.A.Equal(proof.T) || !proof.GasFeePrimeRangeProof.A.Equal(proof.T_fee) {
		log.Println("[Verify WithdrawProof] invalid range params")
		return false, errors.New("[Verify WithdrawProof] invalid rage params")
	}
	// Verify range proof first
	go verifyCtRangeRoutine(proof.BPrimeRangeProof, rangeChan)
	go verifyCtRangeRoutine(proof.GasFeePrimeRangeProof, rangeChan)
	buf.Write(PaddingBigIntBytes(FixedCurve))
	buf.Write(PaddingBigIntBytes(proof.ReceiveAddr))
	// gas fee
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	writeUint64IntoBuf(&buf, uint64(proof.ChainId))
	writeEncIntoBuf(&buf, proof.C)
	writePointIntoBuf(&buf, proof.T)
	writePointIntoBuf(&buf, proof.T_fee)
	writePointIntoBuf(&buf, proof.Pk)
	writePointIntoBuf(&buf, proof.A_pk)
	writePointIntoBuf(&buf, proof.A_TDivCRprime)
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify WithdrawProof] err: unable to compute hash:", err)
		return false, err
	}
	// Verify balance
	balanceRes, err := verifyBalance(G, proof.Pk, proof.A_pk, CLprimeInv, TDivCRprime, proof.A_TDivCRprime, c, proof.Z_sk, proof.Z_skInv, proof.Z_bar_r)
	if err != nil {
		log.Println("err info:", err)
		return false, err
	}
	if !balanceRes {
		log.Println("[Verify WithdrawProof] invalid balance res")
		return false, errors.New("[Verify WithdrawProof] invalid balance res")
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l1 := curve.Add(curve.ScalarMul(G, proof.Z_bar_r_fee), curve.ScalarMul(C_feeLprimeInv, proof.Z_skInv))
	r1 := curve.Add(proof.A_T_feeC_feeRPrimeInv, curve.ScalarMul(T_feeDivC_feeRprime, c))
	if !l1.Equal(r1) {
		log.Println("[Verify WithdrawProof] l1!=r1")
		return false, nil
	}
	for i := 0; i < withdrawRangeProofCount; i++ {
		val := <-rangeChan
		if val == ErrCode {
			log.Println("[Verify AddLiquidityProof] invalid range proof")
			return false, nil
		}
	}
	return balanceRes, nil
}

func commitBalance(g, CLprimeInv *Point) (
	alpha_rbar, alpha_sk, alpha_skInv *big.Int,
	A_pk, A_TDivCRprime *Point,
) {
	alpha_rbar = curve.RandomValue()
	alpha_sk = curve.RandomValue()
	alpha_skInv = ffmath.ModInverse(alpha_sk, Order)
	A_pk = curve.ScalarMul(g, alpha_sk)
	A_TDivCRprime = curve.Add(curve.ScalarMul(g, alpha_rbar), curve.ScalarMul(CLprimeInv, alpha_skInv))
	return
}

func respondBalance(
	rbar, sk, alpha_rbar, alpha_sk, alpha_skInv, c *big.Int,
) (
	z_rbar, z_sk, z_skInv *big.Int,
) {
	z_rbar = ffmath.AddMod(alpha_rbar, ffmath.Multiply(c, rbar), Order)
	z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	skInv := ffmath.ModInverse(sk, Order)
	z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, skInv), Order)
	return
}

/*
	verifyBalance: verify if the owner balance is correct
*/
func verifyBalance(
	g, pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime *Point,
	c *big.Int,
	z_sk, z_skInv, z_rbar *big.Int,
) (bool, error) {
	// Verify pk = g^{sk}
	l1 := curve.ScalarMul(g, z_sk)
	r1 := curve.Add(A_pk, curve.ScalarMul(pk, c))
	if !l1.Equal(r1) {
		log.Println("[verifyBalance] l1!=r1")
		return false, nil
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l2 := curve.Add(curve.ScalarMul(g, z_rbar), curve.ScalarMul(CLprimeInv, z_skInv))
	r2 := curve.Add(A_TDivCRprime, curve.ScalarMul(TDivCRprime, c))
	if !l2.Equal(r2) {
		log.Println("[verifyBalance] l2!=r2")
		return false, nil
	}
	return true, nil
}
