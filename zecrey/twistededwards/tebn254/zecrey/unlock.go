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

func ProveUnlock(
	sk *big.Int, chainId, assetId uint32, balance, deltaAmount uint64,
	// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (proof *UnlockProof, err error) {
	if sk == nil || balance < deltaAmount || !validUint64(balance) || !validUint64(deltaAmount) || B_fee < GasFee {
		log.Println("[ProveUnlock] invalid params")
		return nil, errors.New("[ProveUnlock] invalid params")
	}
	var (
		alpha_sk      *big.Int
		A_pk          *Point
		pk            *Point
		Z_sk, Z_skInv *big.Int
		alpha_skInv   *big.Int
		buf           bytes.Buffer
		c             *big.Int
		// gas fee
		b_feePrime            uint64
		Bar_r_fee             *big.Int
		A_T_feeDivC_feeRprime *Point
		Z_bar_r_fee           *big.Int
		C_feeLPrimeInv        *Point
		alpha_bar_r_fee       *big.Int
		GasFeePrimeRangeProof *RangeProof
	)
	// private key proof
	pk = curve.ScalarMul(G, sk)
	alpha_sk = curve.RandomValue()
	A_pk = curve.ScalarMul(G, alpha_sk)
	// fee proof
	alpha_skInv = ffmath.ModInverse(alpha_sk, Order)
	C_feeLPrimeInv = curve.Neg(C_fee.CL)
	alpha_bar_r_fee = curve.RandomValue()
	A_T_feeDivC_feeRprime = curve.Add(curve.ScalarMul(G, alpha_bar_r_fee), curve.ScalarMul(C_feeLPrimeInv, alpha_skInv))
	buf.Write(FixedCurve.FillBytes(make([]byte, PointSize)))
	writePointIntoBuf(&buf, pk)
	writePointIntoBuf(&buf, A_pk)
	writeUint64IntoBuf(&buf, uint64(chainId))
	writeUint64IntoBuf(&buf, uint64(assetId))
	writeUint64IntoBuf(&buf, balance)
	writeUint64IntoBuf(&buf, deltaAmount)
	// gas fee
	writePointIntoBuf(&buf, A_T_feeDivC_feeRprime)
	writeEncIntoBuf(&buf, C_fee)
	writeUint64IntoBuf(&buf, uint64(GasFeeAssetId))
	writeUint64IntoBuf(&buf, GasFee)
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[ProveUnlock] err info:", err)
		return nil, err
	}
	log.Println(c.String())
	// gas fee range proof
	b_feePrime = B_fee - GasFee
	Bar_r_fee, GasFeePrimeRangeProof, err = proveCtRange(int64(b_feePrime), G, H)
	if err != nil {
		log.Println("[ProveUnlock] unable to prove range proof")
		return nil, err
	}
	Z_bar_r_fee = ffmath.AddMod(alpha_bar_r_fee, ffmath.Multiply(c, Bar_r_fee), Order)
	Z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	Z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, ffmath.ModInverse(sk, Order)), Order)
	proof = &UnlockProof{
		A_pk:                  A_pk,
		A_T_feeC_feeRPrimeInv: A_T_feeDivC_feeRprime,
		Z_bar_r_fee:           Z_bar_r_fee,
		Z_sk:                  Z_sk,
		Z_skInv:               Z_skInv,
		GasFeePrimeRangeProof: GasFeePrimeRangeProof,
		Pk:                    pk,
		ChainId:               chainId,
		AssetId:               assetId,
		Balance:               balance,
		DeltaAmount:           deltaAmount,
		C_fee:                 C_fee,
		T_fee:                 new(Point).Set(GasFeePrimeRangeProof.A),
		GasFeeAssetId:         GasFeeAssetId,
		GasFee:                GasFee,
	}
	return proof, nil
}

func (proof *UnlockProof) Verify() (res bool, err error) {
	if !validUint64(proof.Balance) || !validUint64(proof.DeltaAmount) || !proof.GasFeePrimeRangeProof.A.Equal(proof.T_fee) {
		log.Println("[Verify UnlockProof] invalid params")
		return false, errors.New("[Verify UnlockProof] invalid params")
	}
	var (
		C_feeLprimeNeg      *Point
		T_feeDivC_feeRprime *Point
		buf                 bytes.Buffer
		c                   *big.Int
	)
	buf.Write(FixedCurve.FillBytes(make([]byte, PointSize)))
	writePointIntoBuf(&buf, proof.Pk)
	writePointIntoBuf(&buf, proof.A_pk)
	writeUint64IntoBuf(&buf, uint64(proof.ChainId))
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	writeUint64IntoBuf(&buf, proof.Balance)
	writeUint64IntoBuf(&buf, proof.DeltaAmount)
	// gas fee
	writePointIntoBuf(&buf, proof.A_T_feeC_feeRPrimeInv)
	writeEncIntoBuf(&buf, proof.C_fee)
	writeUint64IntoBuf(&buf, uint64(proof.GasFeeAssetId))
	writeUint64IntoBuf(&buf, proof.GasFee)
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify UnlockProof] err info:", err)
		return false, err
	}
	// check private key
	l1 := curve.ScalarMul(G, proof.Z_sk)
	r1 := curve.Add(proof.A_pk, curve.ScalarMul(proof.Pk, c))
	if !l1.Equal(r1) {
		log.Println("[Verify UnlockProof] l1 != r1")
		return false, errors.New("[Verify UnlockProof] l1 != r1")
	}
	// verify range proof
	verifyRes, err := proof.GasFeePrimeRangeProof.Verify()
	if err != nil {
		log.Println("[Verify UnlockProof] err info:", err)
		return false, err
	}
	if !verifyRes {
		log.Println("[Verify UnlockProof] invalid range proof")
		return false, nil
	}
	// check gas fee proof
	C_feeDelta := curve.ScalarMul(H, big.NewInt(-int64(proof.GasFee)))
	C_feeLprimeNeg = curve.Neg(proof.C_fee.CL)
	T_feeDivC_feeRprime = curve.Add(proof.T_fee, curve.Neg(curve.Add(proof.C_fee.CR, C_feeDelta)))
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l2 := curve.Add(curve.ScalarMul(G, proof.Z_bar_r_fee), curve.ScalarMul(C_feeLprimeNeg, proof.Z_skInv))
	r2 := curve.Add(proof.A_T_feeC_feeRPrimeInv, curve.ScalarMul(T_feeDivC_feeRprime, c))
	if !l2.Equal(r2) {
		log.Println("[Verify UnlockProof] l2!=r2")
		return false, nil
	}
	return true, nil
}
