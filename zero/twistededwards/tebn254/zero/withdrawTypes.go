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
	"encoding/hex"
	"errors"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
	"log"
	"math/big"
)

type WithdrawProof struct {
	// commitments
	A_pk, A_TDivCRprime *Point
	// response
	Z_bar_r, Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	BPrimeRangeProof      *RangeProof
	GasFeePrimeRangeProof *RangeProof
	// common inputs
	BStar       uint64
	C           *ElGamalEnc
	T, Pk       *Point
	ReceiveAddr *big.Int
	AssetId     uint32
	ChainId     uint32
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
}

func (proof *WithdrawProof) Bytes() []byte {
	buf := make([]byte, WithdrawProofSize)
	offset := 0
	offset = copyBuf(&buf, offset, PointSize, proof.A_pk.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.A_TDivCRprime.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.Z_bar_r.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, PointSize, proof.Z_sk.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, PointSize, proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, RangeProofSize, proof.BPrimeRangeProof.Bytes())
	offset = copyBuf(&buf, offset, RangeProofSize, proof.GasFeePrimeRangeProof.Bytes())
	offset = copyBuf(&buf, offset, EightBytes, uint64ToBytes(proof.BStar))
	offset = copyBuf(&buf, offset, ElGamalEncSize, elgamalToBytes(proof.C))
	offset = copyBuf(&buf, offset, PointSize, proof.T.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.Pk.Marshal())
	offset = copyBuf(&buf, offset, AddressSize, proof.ReceiveAddr.FillBytes(make([]byte, AddressSize)))
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.AssetId))
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.ChainId))
	offset = copyBuf(&buf, offset, PointSize, proof.A_T_feeC_feeRPrimeInv.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, ElGamalEncSize, elgamalToBytes(proof.C_fee))
	offset = copyBuf(&buf, offset, PointSize, proof.T_fee.Marshal())
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.GasFeeAssetId))
	offset = copyBuf(&buf, offset, EightBytes, uint64ToBytes(proof.GasFee))
	return buf
}

func (proof *WithdrawProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseWithdrawProofBytes(proofBytes []byte) (proof *WithdrawProof, err error) {
	if len(proofBytes) != WithdrawProofSize {
		log.Println("[ParseWithdrawProofBytes] invalid proof size")
		return nil, ErrInvalidWithdrawProofSize
	}
	proof = new(WithdrawProof)
	offset := 0

	offset, proof.A_pk, err = readPointFromBuf(proofBytes, offset)
	offset, proof.A_TDivCRprime, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_bar_r = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_sk = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_skInv = readBigIntFromBuf(proofBytes, offset)
	offset, proof.BPrimeRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.GasFeePrimeRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.BStar = readUint64FromBuf(proofBytes, offset)
	offset, proof.C, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.T, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.ReceiveAddr = readAddressFromBuf(proofBytes, offset)
	offset, proof.AssetId = readUint32FromBuf(proofBytes, offset)
	offset, proof.ChainId = readUint32FromBuf(proofBytes, offset)
	offset, proof.A_T_feeC_feeRPrimeInv, err = readPointFromBuf(proofBytes, offset)
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
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func ParseWithdrawProofStr(withdrawProofStr string) (*WithdrawProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(withdrawProofStr)
	if err != nil {
		return nil, err
	}
	return ParseWithdrawProofBytes(proofBytes)
}

type WithdrawProofRelation struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// new pedersen commitment for new balance
	T                     *Point
	BPrimeRangeProof      *RangeProof
	GasFeePrimeRangeProof *RangeProof
	// public key
	Pk *Point
	// b^{\star}
	Bstar       uint64
	ReceiveAddr *big.Int
	AssetId     uint32
	ChainId     uint32
	// ----------- private ---------------------
	Sk      *big.Int
	B_prime uint64
	Bar_r   *big.Int
	// gas fee
	C_fee         *ElGamalEnc
	T_fee         *Point
	GasFeeAssetId uint32
	GasFee        uint64
	B_fee_prime   uint64
	R_feeBar      *big.Int
}

func NewWithdrawRelation(
	chainId uint32,
	C *ElGamalEnc,
	pk *Point,
	b uint64, bStar uint64,
	sk *big.Int,
	assetId uint32, receiveAddr string,
	// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (*WithdrawProofRelation, error) {
	if !notNullElGamal(C) || !notNullElGamal(C_fee) || !curve.IsInSubGroup(pk) || sk == nil || b < bStar || B_fee < GasFee ||
		(GasFeeAssetId == assetId && (!equalEnc(C, C_fee) || b < bStar+GasFee || b != B_fee)) || receiveAddr == "" ||
		!validUint64(b) || !validUint64(bStar) || !validUint64(GasFee) {
		log.Println("[NewWithdrawRelation] invalid params")
		return nil, ErrInvalidParams
	}
	addrBytes, err := DecodeAddress(receiveAddr)
	if err != nil {
		log.Println("[NewWithdrawRelation] err info:", err)
		return nil, err
	}
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	var (
		B_prime               uint64
		b_fee_prime           uint64
		Bar_r                 = new(big.Int)
		Bar_r_fee             = new(big.Int)
		BPrimeRangeProof      = new(RangeProof)
		GasFeePrimeRangeProof = new(RangeProof)
		addrInt               *big.Int
	)
	// check if the b is correct
	hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
	hbCheck := curve.ScalarMul(H, big.NewInt(int64(b)))
	if !hb.Equal(hbCheck) {
		log.Println("[NewWithdrawRelation] incorrect balance")
		return nil, ErrIncorrectBalance
	}
	// b' = b - b^{\star} - fee
	if assetId == GasFeeAssetId {
		B_prime = b - bStar - GasFee
		// T = g^{\bar{rStar}} h^{b'}
		Bar_r, BPrimeRangeProof, err = proveCtRange(int64(B_prime), G, H)
		if err != nil {
			log.Println("[NewWithdrawRelation] err range proof:", err)
			return nil, err
		}
		b_fee_prime = B_prime
		Bar_r_fee = new(big.Int)
		Bar_r_fee.Set(Bar_r)
		GasFeePrimeRangeProof = BPrimeRangeProof
	} else {
		// prove enough balance
		B_prime = b - bStar
		// T = g^{\bar{rStar}} h^{b'}
		var (
			withdrawRangeChan = make(chan int, buyNftRangeProofCount)
		)
		go proveCtRangeRoutine(int64(B_prime), G, H, Bar_r, BPrimeRangeProof, withdrawRangeChan)
		// prove enough fee
		b_fee_prime = B_fee - GasFee
		go proveCtRangeRoutine(int64(b_fee_prime), G, H, Bar_r_fee, GasFeePrimeRangeProof, withdrawRangeChan)
		for i := 0; i < buyNftRangeProofCount; i++ {
			val := <-withdrawRangeChan
			if val == ErrCode {
				return nil, errors.New("[NewWithdrawRelation] range proof works error")
			}
		}
	}
	// compute Ha
	addrInt = new(big.Int).SetBytes(addrBytes)
	relation := &WithdrawProofRelation{
		C:                     C,
		T:                     new(Point).Set(BPrimeRangeProof.A),
		BPrimeRangeProof:      BPrimeRangeProof,
		GasFeePrimeRangeProof: GasFeePrimeRangeProof,
		Pk:                    pk,
		Bstar:                 bStar,
		ReceiveAddr:           addrInt,
		AssetId:               assetId,
		ChainId:               uint32(chainId),
		Sk:                    sk,
		B_prime:               B_prime,
		Bar_r:                 Bar_r,
		C_fee:                 C_fee,
		T_fee:                 new(Point).Set(GasFeePrimeRangeProof.A),
		GasFeeAssetId:         GasFeeAssetId,
		GasFee:                GasFee,
		B_fee_prime:           b_fee_prime,
		R_feeBar:              Bar_r_fee,
	}
	return relation, nil
}

func DecodeAddress(addr string) ([]byte, error) {
	if len(addr) != 42 {
		return nil, errors.New("[DecodeAddress] invalid address")
	}
	addrBytes, err := hex.DecodeString(addr[2:])
	if err != nil {
		return nil, err
	}
	if len(addrBytes) != AddressSize {
		log.Println("[DecodeAddress] invalid address")
		return nil, errors.New("[DecodeAddress] invalid address")
	}
	return addrBytes, nil
}
