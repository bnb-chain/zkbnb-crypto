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
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

type WithdrawProof struct {
	// commitments
	A_pk, A_TDivCRprime, A_Pa *Point
	// response
	Z_rbar, Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	BPrimeRangeProof *RangeProof
	// common inputs
	Pa              *Point
	BStar           uint64
	Fee             uint64
	CRStar          *Point
	C               *ElGamalEnc
	G, H, Ha, T, Pk *Point
	ReceiveAddr     *big.Int
}

func (proof *WithdrawProof) Bytes() []byte {
	res := make([]byte, WithdrawProofSize)
	copy(res[:PointSize], proof.Pa.Marshal())
	copy(res[PointSize:PointSize*2], proof.A_pk.Marshal())
	copy(res[PointSize*2:PointSize*3], proof.A_TDivCRprime.Marshal())
	copy(res[PointSize*3:PointSize*4], proof.A_Pa.Marshal())
	copy(res[PointSize*4:PointSize*5], proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*5:PointSize*6], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*6:PointSize*7], proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*7:PointSize*8], proof.CRStar.Marshal())
	C := proof.C.Bytes()
	copy(res[PointSize*8:PointSize*10], C[:])
	copy(res[PointSize*10:PointSize*11], proof.G.Marshal())
	copy(res[PointSize*11:PointSize*12], proof.H.Marshal())
	copy(res[PointSize*12:PointSize*13], proof.Ha.Marshal())
	copy(res[PointSize*13:PointSize*14], proof.T.Marshal())
	copy(res[PointSize*14:PointSize*15], proof.Pk.Marshal())
	BStarBytes := make([]byte, EightBytes)
	FeeBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(BStarBytes, proof.BStar)
	binary.BigEndian.PutUint64(FeeBytes, proof.Fee)
	copy(res[PointSize*15:PointSize*15+EightBytes], BStarBytes)
	copy(res[PointSize*15+EightBytes:PointSize*15+EightBytes*2], FeeBytes)
	copy(res[PointSize*15+EightBytes*2:PointSize*15+EightBytes*2+AddressSize], proof.ReceiveAddr.FillBytes(make([]byte, AddressSize)))
	copy(res[PointSize*15+EightBytes*2+AddressSize:PointSize*15+EightBytes*2+AddressSize+RangeProofSize], proof.BPrimeRangeProof.Bytes())
	return res
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
	proof.Pa, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_pk, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.A_TDivCRprime, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.A_Pa, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.Z_rbar = new(big.Int).SetBytes(proofBytes[PointSize*4 : PointSize*5])
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize*5 : PointSize*6])
	proof.Z_skInv = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.CRStar, err = curve.FromBytes(proofBytes[PointSize*7 : PointSize*8])
	if err != nil {
		return nil, err
	}
	proof.C, err = twistedElgamal.FromBytes(proofBytes[PointSize*8 : PointSize*10])
	if err != nil {
		return nil, err
	}
	proof.G, err = curve.FromBytes(proofBytes[PointSize*10 : PointSize*11])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*11 : PointSize*12])
	if err != nil {
		return nil, err
	}
	proof.Ha, err = curve.FromBytes(proofBytes[PointSize*12 : PointSize*13])
	if err != nil {
		return nil, err
	}
	proof.T, err = curve.FromBytes(proofBytes[PointSize*13 : PointSize*14])
	if err != nil {
		return nil, err
	}
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*14 : PointSize*15])
	if err != nil {
		return nil, err
	}
	proof.BStar = binary.BigEndian.Uint64(proofBytes[PointSize*15 : PointSize*15+EightBytes])
	proof.Fee = binary.BigEndian.Uint64(proofBytes[PointSize*15+EightBytes : PointSize*15+EightBytes*2])
	proof.ReceiveAddr = new(big.Int).SetBytes(proofBytes[PointSize*15+EightBytes*2 : PointSize*15+EightBytes*2+AddressSize])
	proof.BPrimeRangeProof, err = ctrange.FromBytes(proofBytes[PointSize*15+EightBytes*2+AddressSize:])
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
	// delta balance enc
	CRStar *Point
	// new pedersen commitment for new balance
	T                *Point
	BPrimeRangeProof *RangeProof
	// public key
	Pk *Point
	// Ha = h^{addr}
	Ha *Point
	// Pa = Ha^{sk}
	Pa *Point
	// generator 1
	G *Point
	// generator 2
	H *Point
	// token Id
	TokenId uint32
	// b^{\star}
	Bstar uint64
	// fee
	Fee uint64
	// ----------- private ---------------------
	Sk          *big.Int
	BPrime      uint64
	RBar        *big.Int
	ReceiveAddr *big.Int
}

func NewWithdrawRelation(
	C *ElGamalEnc,
	pk *Point,
	b uint64, bStar uint64,
	sk *big.Int,
	assetId uint32, receiveAddr string, fee uint64,
) (*WithdrawProofRelation, error) {
	if !notNullElGamal(C) || !curve.IsInSubGroup(pk) || sk == nil || b < bStar+fee || receiveAddr == "" ||
		!validUint64(b) || !validUint64(bStar) || !validUint64(fee) {
		log.Println("[NewWithdrawRelation] invalid params")
		return nil, ErrInvalidParams
	}
	addrBytes, err := decodeAddress(receiveAddr)
	if err != nil {
		log.Println("[NewWithdrawRelation] err info:", err)
		return nil, err
	}
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	var (
		bPrime           uint64
		rBar             *big.Int
		BPrimeRangeProof *RangeProof
		addrInt          *big.Int
	)
	// check if the b is correct
	hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
	hbCheck := curve.ScalarMul(H, big.NewInt(int64(b)))
	if !hb.Equal(hbCheck) {
		log.Println("[NewWithdrawRelation] incorrect balance")
		return nil, ErrIncorrectBalance
	}
	// b' = b - b^{\star} - fee
	bPrime = b - bStar - fee
	// C^{\Delta} = (pk^rStar,G^rStar h^{b^{\Delta} - fee})
	hNeg := curve.Neg(H)
	CRStar := curve.ScalarMul(hNeg, big.NewInt(int64(bStar+fee)))
	// compute \bar{r} = \sum_{i=1}^32 r_i
	// T = g^{\bar{rStar}} h^{b'}
	rBar, BPrimeRangeProof, err = proveCtRange(int64(bPrime), G, H)
	if err != nil {
		log.Println("[NewWithdrawRelation] err range proof:", err)
		return nil, err
	}
	// compute Ha
	addrInt = new(big.Int).SetBytes(addrBytes)
	Ha := curve.ScalarMul(H, addrInt)
	relation := &WithdrawProofRelation{
		// ------------- public ---------------------
		C:                C,
		CRStar:           CRStar,
		T:                new(Point).Set(BPrimeRangeProof.A),
		Pk:               pk,
		G:                G,
		H:                H,
		Ha:               Ha,
		TokenId:          assetId,
		Bstar:            bStar,
		Fee:              fee,
		BPrimeRangeProof: BPrimeRangeProof,
		// ----------- private ---------------------
		Sk:          sk,
		BPrime:      bPrime,
		RBar:        rBar,
		ReceiveAddr: addrInt,
	}
	relation.Pa = curve.ScalarMul(relation.Ha, sk)
	return relation, nil
}

func decodeAddress(addr string) ([]byte, error) {
	if addr[:2] == "0x" {
		addrBytes, err := hex.DecodeString(addr[2:])
		if err != nil {
			log.Println("[decodeAddress] decode error")
			return nil, err
		}
		if len(addrBytes) != AddressSize {
			log.Println("[decodeAddress] invalid address")
			return nil, errors.New("[decodeAddress] invalid address")
		}
		return addrBytes, nil
	}
	addrBytes, err := hex.DecodeString(addr[:])
	if err != nil {
		return nil, err
	}
	if len(addrBytes) != AddressSize {
		log.Println("[decodeAddress] invalid address")
		return nil, errors.New("[decodeAddress] invalid address")
	}
	return addrBytes, nil
}
