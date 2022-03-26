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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/util"
	"log"
	"math/big"
)

func ProveClaimNft(relation *ClaimNftRelation) (proof *ClaimNftProof, err error) {
	if relation == nil {
		log.Println("[ProveWithdrawNft] invalid params")
		return nil, ErrInvalidParams
	}
	var (
		alpha_bar_r_fee, alpha_sk, alpha_skInv *big.Int
		A_pk, A_T_feeDivC_feeRprime            *Point
		C_feeLPrimeInv                         *Point
		buf                                    bytes.Buffer
		z_bar_r_fee, z_sk, z_skInv             *big.Int
	)
	// balance part
	alpha_sk = curve.RandomValue()
	alpha_skInv = ffmath.ModInverse(alpha_sk, Order)
	A_pk = curve.ScalarMul(G, alpha_sk)
	// fee part
	C_feeLPrimeInv = curve.Neg(relation.C_fee.CL)
	alpha_bar_r_fee = curve.RandomValue()
	A_T_feeDivC_feeRprime = curve.Add(curve.ScalarMul(G, alpha_bar_r_fee), curve.ScalarMul(C_feeLPrimeInv, alpha_skInv))
	// write common inputs into buf
	// then generate the challenge c
	buf.Write(PaddingBigIntBytes(FixedCurve))
	// gas fee
	writeEncIntoBuf(&buf, relation.C_fee)
	writeUint64IntoBuf(&buf, uint64(relation.GasFeeAssetId))
	writeUint64IntoBuf(&buf, relation.GasFee)
	writePointIntoBuf(&buf, relation.T_fee)
	writePointIntoBuf(&buf, relation.Pk)
	writeUint64IntoBuf(&buf, uint64(relation.TxType))
	buf.Write(relation.NftContentHash)
	writeUint64IntoBuf(&buf, uint64(relation.ReceiverAccountIndex))
	writePointIntoBuf(&buf, A_pk)
	writePointIntoBuf(&buf, A_T_feeDivC_feeRprime)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, relation.Sk), Order)
	skInv := ffmath.ModInverse(relation.Sk, Order)
	z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, skInv), Order)
	z_bar_r_fee = ffmath.AddMod(alpha_bar_r_fee, ffmath.Multiply(c, relation.Bar_r_fee), Order)
	proof = &ClaimNftProof{
		A_pk:                  A_pk,
		Z_sk:                  z_sk,
		Z_skInv:               z_skInv,
		GasFeePrimeRangeProof: relation.GasFeePrimeRangeProof,
		Pk:                    relation.Pk,
		TxType:                relation.TxType,
		NftContentHash:        relation.NftContentHash,
		ReceiverAccountIndex:  relation.ReceiverAccountIndex,
		A_T_feeC_feeRPrimeInv: A_T_feeDivC_feeRprime,
		Z_bar_r_fee:           z_bar_r_fee,
		C_fee:                 relation.C_fee,
		T_fee:                 relation.T_fee,
		GasFeeAssetId:         relation.GasFeeAssetId,
		GasFee:                relation.GasFee,
	}
	return proof, nil
}

func (proof *ClaimNftProof) Verify() (bool, error) {
	if !validUint64(proof.GasFee) {
		log.Println("[Verify SetNftPriceProof] invalid params")
		return false, errors.New("[Verify SetNftPriceProof] invalid params")
	}
	// generate the challenge
	var (
		C_feeLprimeInv, T_feeDivC_feeRprime *Point
		buf                                 bytes.Buffer
	)
	// check params
	C_feeDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee)))
	C_feeLprimeInv = curve.Neg(proof.C_fee.CL)
	T_feeDivC_feeRprime = curve.Add(proof.T_fee, curve.Neg(curve.Add(proof.C_fee.CR, C_feeDelta)))
	// check range params
	if !proof.GasFeePrimeRangeProof.A.Equal(proof.T_fee) {
		log.Println("[Verify SetNftPriceProof] invalid range params")
		return false, errors.New("[Verify SetNftPriceProof] invalid rage params")
	}
	// Verify range proof first
	isValidProof, err := proof.GasFeePrimeRangeProof.Verify()
	if err != nil {
		log.Println("[Verify SetNftPriceProof] unable to verify gas fee prime range proof:", err)
		return false, err
	}
	if !isValidProof {
		log.Println("[Verify SetNftPriceProof] invalid range proof")
		return false, nil
	}
	buf.Write(PaddingBigIntBytes(FixedCurve))
	// gas fee
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writePointIntoBuf(&buf, proof.T_fee)
	writePointIntoBuf(&buf, proof.Pk)
	writeUint64IntoBuf(&buf, uint64(proof.TxType))
	buf.Write(proof.NftContentHash)
	writeUint64IntoBuf(&buf, uint64(proof.ReceiverAccountIndex))
	writePointIntoBuf(&buf, proof.A_pk)
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify SetNftPriceProof] err: unable to compute hash:", err)
		return false, err
	}
	// Verify balance
	// Verify pk = g^{sk}
	l1 := curve.ScalarMul(G, proof.Z_sk)
	r1 := curve.Add(proof.A_pk, curve.ScalarMul(proof.Pk, c))
	if !l1.Equal(r1) {
		log.Println("[Verify SetNftPriceProof] l1!=r1")
		return false, nil
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l2 := curve.Add(curve.ScalarMul(G, proof.Z_bar_r_fee), curve.ScalarMul(C_feeLprimeInv, proof.Z_skInv))
	r2 := curve.Add(proof.A_T_feeC_feeRPrimeInv, curve.ScalarMul(T_feeDivC_feeRprime, c))
	if !l2.Equal(r2) {
		log.Println("[Verify SetNftPriceProof] l2!=r2")
		return false, nil
	}
	return true, nil
}
