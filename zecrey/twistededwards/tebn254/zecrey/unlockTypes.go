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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

type UnlockProof struct {
	// A
	A_pk *Point
	// Z
	Z_sk *big.Int
	// common inputs
	Pk          *Point
	ChainId     uint32
	AssetId     uint32
	Balance     uint64
	DeltaAmount uint64
}

func (proof *UnlockProof) Bytes() []byte {
	proofBytes := make([]byte, UnlockProofSize)
	copy(proofBytes[:PointSize], proof.A_pk.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*2:PointSize*3], proof.Pk.Marshal())
	chainIdBytes := make([]byte, FourBytes)
	assetIdBytes := make([]byte, FourBytes)
	BalanceBytes := make([]byte, EightBytes)
	DeltaAmountBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint32(chainIdBytes, proof.ChainId)
	binary.BigEndian.PutUint32(assetIdBytes, proof.AssetId)
	binary.BigEndian.PutUint64(BalanceBytes, proof.Balance)
	binary.BigEndian.PutUint64(DeltaAmountBytes, proof.DeltaAmount)
	copy(proofBytes[PointSize*3:PointSize*3+FourBytes], chainIdBytes)
	copy(proofBytes[PointSize*3+FourBytes:PointSize*3+FourBytes*2], assetIdBytes)
	copy(proofBytes[PointSize*3+FourBytes*2:PointSize*3+FourBytes*2+EightBytes], BalanceBytes)
	copy(proofBytes[PointSize*3+FourBytes*2+EightBytes:PointSize*3+FourBytes*2+EightBytes*2], DeltaAmountBytes)
	return proofBytes
}

func (proof *UnlockProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseUnlockProofBytes(proofBytes []byte) (proof *UnlockProof, err error) {
	if len(proofBytes) != UnlockProofSize {
		log.Println("[ParseUnlockProofBytes] invalid proof size")
		return nil, errors.New("[ParseUnlockProofBytes] invalid proof size")
	}
	proof = new(UnlockProof)
	proof.A_pk, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize : PointSize*2])
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.ChainId = binary.BigEndian.Uint32(proofBytes[PointSize*3 : PointSize*3+FourBytes])
	proof.AssetId = binary.BigEndian.Uint32(proofBytes[PointSize*3+FourBytes : PointSize*3+FourBytes*2])
	proof.Balance = binary.BigEndian.Uint64(proofBytes[PointSize*3+FourBytes*2 : PointSize*3+FourBytes*2+EightBytes])
	proof.DeltaAmount = binary.BigEndian.Uint64(proofBytes[PointSize*3+FourBytes*2+EightBytes : PointSize*3+FourBytes*2+EightBytes*2])
	return proof, nil
}

func ParseUnlockProofStr(proofStr string) (proof *UnlockProof, err error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseUnlockProofBytes(proofBytes)
}
