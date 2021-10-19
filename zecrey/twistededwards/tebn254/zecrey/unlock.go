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
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func ProveUnlock(sk *big.Int, chainId, assetId uint32, balance, deltaAmount uint64) (proof *UnlockProof, err error) {
	if sk == nil || balance < deltaAmount || !validUint64(balance) || !validUint64(deltaAmount) {
		log.Println("[ProveUnlock] invalid params")
		return nil, errors.New("[ProveUnlock] invalid params")
	}
	var (
		alpha_sk *big.Int
		A_pk     *Point
		pk       *Point
		Z_sk     *big.Int
		buf      bytes.Buffer
		c        *big.Int
	)
	pk = curve.ScalarMul(G, sk)
	alpha_sk = curve.RandomValue()
	A_pk = curve.ScalarMul(G, alpha_sk)
	buf.Write(FixedCurve.FillBytes(make([]byte, PointSize)))
	writePointIntoBuf(&buf, pk)
	writePointIntoBuf(&buf, A_pk)
	writeUint64IntoBuf(&buf, uint64(chainId))
	writeUint64IntoBuf(&buf, uint64(assetId))
	writeUint64IntoBuf(&buf, balance)
	writeUint64IntoBuf(&buf, deltaAmount)
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[ProveUnlock] err info:", err)
		return nil, err
	}
	Z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	proof = &UnlockProof{
		A_pk:        A_pk,
		Z_sk:        Z_sk,
		Pk:          pk,
		ChainId:     chainId,
		AssetId:     assetId,
		Balance:     balance,
		DeltaAmount: deltaAmount,
	}
	return proof, nil
}

func (proof *UnlockProof) Verify() (res bool, err error) {
	if !validUint64(proof.Balance) || !validUint64(proof.DeltaAmount) {
		log.Println("[Verify UnlockProof] invalid params")
		return false, errors.New("[Verify UnlockProof] invalid params")
	}
	var (
		buf bytes.Buffer
		c   *big.Int
	)
	buf.Write(FixedCurve.FillBytes(make([]byte, PointSize)))
	writePointIntoBuf(&buf, proof.Pk)
	writePointIntoBuf(&buf, proof.A_pk)
	writeUint64IntoBuf(&buf, uint64(proof.ChainId))
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	writeUint64IntoBuf(&buf, proof.Balance)
	writeUint64IntoBuf(&buf, proof.DeltaAmount)
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify UnlockProof] err info:", err)
		return false, err
	}
	l := curve.ScalarMul(G, proof.Z_sk)
	r := curve.Add(proof.A_pk, curve.ScalarMul(proof.Pk, c))
	if !l.Equal(r) {
		log.Println("[Verify UnlockProof] l != r")
		return false, errors.New("[Verify UnlockProof] l != r")
	}
	return true, nil
}
