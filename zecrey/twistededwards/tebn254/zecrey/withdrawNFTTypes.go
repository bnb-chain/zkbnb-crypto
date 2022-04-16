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
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"log"
	"math/big"
)

type WithdrawNftProof struct {
	// commitments
	A_pk *Point
	// response
	Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	GasFeePrimeRangeProof *RangeProof
	// common inputs
	Pk          *Point
	TxType      uint32
	NftIndex    uint32
	ReceiveAddr *big.Int
	ProxyAddr   *big.Int
	ChainId     uint32
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
}

func (proof *WithdrawNftProof) Bytes() []byte {
	buf := make([]byte, WithdrawNftProofSize)
	offset := 0
	offset = copyBuf(&buf, offset, PointSize, proof.A_pk.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.Z_sk.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, PointSize, proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, RangeProofSize, proof.GasFeePrimeRangeProof.Bytes())
	offset = copyBuf(&buf, offset, PointSize, proof.Pk.Marshal())
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.TxType))
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.NftIndex))
	offset = copyBuf(&buf, offset, AddressSize, proof.ReceiveAddr.FillBytes(make([]byte, AddressSize)))
	offset = copyBuf(&buf, offset, AddressSize, proof.ProxyAddr.FillBytes(make([]byte, AddressSize)))
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.ChainId))
	offset = copyBuf(&buf, offset, PointSize, proof.A_T_feeC_feeRPrimeInv.Marshal())
	offset = copyBuf(&buf, offset, PointSize, proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&buf, offset, ElGamalEncSize, elgamalToBytes(proof.C_fee))
	offset = copyBuf(&buf, offset, PointSize, proof.T_fee.Marshal())
	offset = copyBuf(&buf, offset, FourBytes, uint32ToBytes(proof.GasFeeAssetId))
	offset = copyBuf(&buf, offset, EightBytes, uint64ToBytes(proof.GasFee))
	return buf
}

func (proof *WithdrawNftProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseWithdrawNftProofBytes(proofBytes []byte) (proof *WithdrawNftProof, err error) {
	if len(proofBytes) != WithdrawNftProofSize {
		log.Println("[ParseWithdrawNftProofBytes] invalid proof size")
		return nil, errors.New("[ParseWithdrawNftProofBytes] invalid nft proof size")
	}
	proof = new(WithdrawNftProof)
	offset := 0

	offset, proof.A_pk, err = readPointFromBuf(proofBytes, offset)
	offset, proof.Z_sk = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_skInv = readBigIntFromBuf(proofBytes, offset)
	offset, proof.GasFeePrimeRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.TxType = readUint32FromBuf(proofBytes, offset)
	offset, proof.NftIndex = readUint32FromBuf(proofBytes, offset)
	offset, proof.ReceiveAddr = readAddressFromBuf(proofBytes, offset)
	offset, proof.ProxyAddr = readAddressFromBuf(proofBytes, offset)
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

func ParseWithdrawNftProofStr(mintNftProofStr string) (*WithdrawNftProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(mintNftProofStr)
	if err != nil {
		return nil, err
	}
	return ParseWithdrawNftProofBytes(proofBytes)
}

type WithdrawNftRelation struct {
	// ------------- public ---------------------
	GasFeePrimeRangeProof *RangeProof
	// public key
	Pk           *Point
	TxType       uint32
	NftIndex     uint32
	ReceiverAddr *big.Int
	ProxyAddr    *big.Int
	ChainId      uint32
	// ----------- private ---------------------
	Sk *big.Int
	// gas fee
	C_fee         *ElGamalEnc
	T_fee         *Point
	GasFeeAssetId uint32
	GasFee        uint64
	B_fee_prime   uint64
	Bar_r_fee     *big.Int
}

func NewWithdrawNftRelation(
	pk *Point,
	txType uint32,
	nftIndex uint32,
	receiverAddr, proxyAddr string,
	chainId uint32,
	sk *big.Int,
	// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (*WithdrawNftRelation, error) {
	if !notNullElGamal(C_fee) || !curve.IsInSubGroup(pk) || sk == nil || B_fee < GasFee ||
		!validUint64(GasFee) || receiverAddr == "" || proxyAddr == "" {
		log.Println("[NewSetNftPriceRelation] invalid params")
		return nil, ErrInvalidParams
	}
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		log.Println("[NewSetNftPriceRelation] inconsistent public key")
		return nil, ErrInconsistentPublicKey
	}
	var (
		b_fee_prime           uint64
		Bar_r_fee             = new(big.Int)
		GasFeePrimeRangeProof = new(RangeProof)
		err                   error
		addrInt               *big.Int
	)
	// check if the b is correct
	hb_fee := curve.Add(C_fee.CR, curve.Neg(curve.ScalarMul(C_fee.CL, ffmath.ModInverse(sk, Order))))
	hb_feeCheck := curve.ScalarMul(H, big.NewInt(int64(B_fee)))
	if !hb_fee.Equal(hb_feeCheck) {
		log.Println("[NewSetNftPriceRelation] incorrect balance")
		return nil, ErrIncorrectBalance
	}
	// b' = b_fee - fee
	b_fee_prime = B_fee - GasFee
	// T = g^{\bar{rStar}} h^{b'}
	Bar_r_fee, GasFeePrimeRangeProof, err = proveCtRange(int64(b_fee_prime), G, H)
	if err != nil {
		log.Println("[NewWithdrawRelation] err range proof:", err)
		return nil, err
	}
	addrBytes, err := DecodeAddress(receiverAddr)
	if err != nil {
		log.Println("[NewWithdrawRelation] err info:", err)
		return nil, err
	}
	addrInt = new(big.Int).SetBytes(addrBytes)
	proxyAddrBytes, err := DecodeAddress(receiverAddr)
	if err != nil {
		log.Println("[NewWithdrawRelation] err info:", err)
		return nil, err
	}
	proxyInt := new(big.Int).SetBytes(proxyAddrBytes)
	relation := &WithdrawNftRelation{
		GasFeePrimeRangeProof: GasFeePrimeRangeProof,
		Pk:                    pk,
		TxType:                txType,
		NftIndex:              nftIndex,
		ReceiverAddr:          addrInt,
		ProxyAddr:             proxyInt,
		ChainId:               chainId,
		Sk:                    sk,
		C_fee:                 C_fee,
		T_fee:                 new(Point).Set(GasFeePrimeRangeProof.A),
		GasFeeAssetId:         GasFeeAssetId,
		GasFee:                GasFee,
		B_fee_prime:           b_fee_prime,
		Bar_r_fee:             Bar_r_fee,
	}
	return relation, nil
}
