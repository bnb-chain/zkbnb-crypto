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

package zero

import (
	"bytes"
	"errors"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
	"github.com/bnb-chain/zkbas-crypto/hash/bn254/zmimc"
	"github.com/bnb-chain/zkbas-crypto/util"
	"log"
	"math/big"
)

const (
	buyNftRangeProofCount = 2
)

func ProveBuyNft(relation *BuyNftProofRelation) (proof *BuyNftProof, err error) {
	if relation == nil {
		log.Println("[ProveBuyNft] invalid params")
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
	writeUint64IntoBuf(&buf, uint64(proof.NftIndex))
	// gas fee
	writeEncIntoBuf(&buf, relation.C_fee)
	writeUint64IntoBuf(&buf, uint64(relation.GasFeeAssetId))
	writeUint64IntoBuf(&buf, relation.GasFee)
	writeUint64IntoBuf(&buf, uint64(relation.NftAssetId))
	writeUint64IntoBuf(&buf, relation.NftIndex)
	buf.Write(relation.NftContentHash)
	writeUint64IntoBuf(&buf, uint64(relation.AssetId))
	writeUint64IntoBuf(&buf, relation.AssetAmount)
	writeUint64IntoBuf(&buf, uint64(relation.FeeRate))
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
	proof = &BuyNftProof{
		A_pk:                  A_pk,
		A_TDivCRprime:         A_TDivCRprime,
		Z_bar_r:               z_bar_r,
		Z_sk:                  z_sk,
		Z_skInv:               z_skInv,
		BPrimeRangeProof:      relation.BPrimeRangeProof,
		GasFeePrimeRangeProof: relation.GasFeePrimeRangeProof,
		C:                     relation.C,
		T:                     relation.T,
		Pk:                    relation.Pk,
		NftIndex:              relation.NftIndex,
		AssetId:               relation.AssetId,
		AssetAmount:           relation.AssetAmount,
		FeeRate:               relation.FeeRate,
		A_T_feeC_feeRPrimeInv: A_T_feeDivC_feeRprime,
		Z_bar_r_fee:           z_bar_r_fee,
		C_fee:                 relation.C_fee,
		T_fee:                 relation.T_fee,
		GasFeeAssetId:         relation.GasFeeAssetId,
		GasFee:                relation.GasFee,
	}
	return proof, nil
}

func (proof *BuyNftProof) Verify() (bool, error) {
	if !validUint64(proof.AssetAmount) || !validUint64(proof.GasFee) {
		log.Println("[Verify BuyNftProof] invalid params")
		return false, errors.New("[Verify BuyNftProof] invalid params")
	}
	// generate the challenge
	var (
		CLprimeInv, C_feeLprimeInv, TDivCRprime, T_feeDivC_feeRprime *Point
		buf                                                          bytes.Buffer
		rangeChan                                                    = make(chan int, buyNftRangeProofCount)
	)
	// check params
	if proof.GasFeeAssetId == proof.AssetId {
		if !equalEnc(proof.C, proof.C_fee) || !proof.A_TDivCRprime.Equal(proof.A_T_feeC_feeRPrimeInv) {
			log.Println("[Verify BuyNftProof] invalid params")
			return false, errors.New("[Verify BuyNftProof] invalid params")
		}
		CRDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.AssetAmount+proof.GasFee)))
		CLprimeInv = curve.Neg(proof.C.CL)
		TDivCRprime = curve.Add(proof.T, curve.Neg(curve.Add(proof.C.CR, CRDelta)))
		C_feeLprimeInv = new(Point).Set(CLprimeInv)
		T_feeDivC_feeRprime = new(Point).Set(TDivCRprime)
	} else {
		CRDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.AssetAmount)))
		C_feeDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee)))
		CLprimeInv = curve.Neg(proof.C.CL)
		TDivCRprime = curve.Add(proof.T, curve.Neg(curve.Add(proof.C.CR, CRDelta)))
		C_feeLprimeInv = curve.Neg(proof.C_fee.CL)
		T_feeDivC_feeRprime = curve.Add(proof.T_fee, curve.Neg(curve.Add(proof.C_fee.CR, C_feeDelta)))
	}
	// check range params
	if !proof.BPrimeRangeProof.A.Equal(proof.T) || !proof.GasFeePrimeRangeProof.A.Equal(proof.T_fee) {
		log.Println("[Verify BuyNftProof] invalid range params")
		return false, errors.New("[Verify BuyNftProof] invalid rage params")
	}
	// Verify range proof first
	go verifyCtRangeRoutine(proof.BPrimeRangeProof, rangeChan)
	go verifyCtRangeRoutine(proof.GasFeePrimeRangeProof, rangeChan)
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writeUint64IntoBuf(&buf, uint64(proof.NftIndex))
	// gas fee
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writeUint64IntoBuf(&buf, uint64(proof.NftAssetId))
	writeUint64IntoBuf(&buf, proof.NftIndex)
	buf.Write(proof.NftContentHash)
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	writeUint64IntoBuf(&buf, proof.AssetAmount)
	writeUint64IntoBuf(&buf, uint64(proof.FeeRate))
	writeEncIntoBuf(&buf, proof.C)
	writePointIntoBuf(&buf, proof.T)
	writePointIntoBuf(&buf, proof.T_fee)
	writePointIntoBuf(&buf, proof.Pk)
	writePointIntoBuf(&buf, proof.A_pk)
	writePointIntoBuf(&buf, proof.A_TDivCRprime)
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify BuyNftProof] err: unable to compute hash:", err)
		return false, err
	}
	// Verify balance
	balanceRes, err := verifyBalance(G, proof.Pk, proof.A_pk, CLprimeInv, TDivCRprime, proof.A_TDivCRprime, c, proof.Z_sk, proof.Z_skInv, proof.Z_bar_r)
	if err != nil {
		log.Println("err info:", err)
		return false, err
	}
	if !balanceRes {
		log.Println("[Verify BuyNftProof] invalid balance res")
		return false, errors.New("[Verify BuyNftProof] invalid balance res")
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l1 := curve.Add(curve.ScalarMul(G, proof.Z_bar_r_fee), curve.ScalarMul(C_feeLprimeInv, proof.Z_skInv))
	r1 := curve.Add(proof.A_T_feeC_feeRPrimeInv, curve.ScalarMul(T_feeDivC_feeRprime, c))
	if !l1.Equal(r1) {
		log.Println("[Verify BuyNftProof] l1!=r1")
		return false, nil
	}
	for i := 0; i < buyNftRangeProofCount; i++ {
		val := <-rangeChan
		if val == ErrCode {
			log.Println("[Verify AddLiquidityProof] invalid range proof")
			return false, nil
		}
	}
	return balanceRes, nil
}
