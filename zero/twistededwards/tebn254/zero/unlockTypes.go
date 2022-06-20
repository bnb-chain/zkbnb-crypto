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
	"encoding/base64"
	"errors"
	"log"
	"math/big"
)

type UnlockProof struct {
	// A
	A_pk *Point
	// response
	Z_sk, Z_skInv         *big.Int
	GasFeePrimeRangeProof *RangeProof
	// common inputs
	Pk          *Point
	ChainId     uint32
	AssetId     uint32
	Balance     uint64
	DeltaAmount uint64
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
}

func (proof *UnlockProof) Bytes() []byte {
	proofBytes := make([]byte, UnlockProofSize)
	offset := 0
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_pk.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk.Marshal())
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.ChainId))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetId))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.Balance))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.DeltaAmount))
	// gas fee part
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_feeC_feeRPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_fee))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_fee.Marshal())
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.GasFeeAssetId))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.GasFee))
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.GasFeePrimeRangeProof.Bytes())
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
	offset := 0
	offset, proof.A_pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_sk = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_skInv = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.ChainId = readUint32FromBuf(proofBytes, offset)
	offset, proof.AssetId = readUint32FromBuf(proofBytes, offset)
	offset, proof.Balance = readUint64FromBuf(proofBytes, offset)
	offset, proof.DeltaAmount = readUint64FromBuf(proofBytes, offset)
	offset, proof.A_T_feeC_feeRPrimeInv,err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_bar_r_fee = readBigIntFromBuf(proofBytes, offset)
	offset, proof.C_fee, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.T_fee, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.GasFeeAssetId = readUint32FromBuf(proofBytes, offset)
	offset, proof.GasFee = readUint64FromBuf(proofBytes, offset)
	offset, proof.GasFeePrimeRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ParseUnlockProofStr(proofStr string) (proof *UnlockProof, err error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseUnlockProofBytes(proofBytes)
}
