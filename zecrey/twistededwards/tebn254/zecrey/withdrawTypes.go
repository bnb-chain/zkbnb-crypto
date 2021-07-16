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
	"encoding/base64"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

type WithdrawProof struct {
	// commitments
	Pt, Pa                          *Point
	A_pk, A_TDivCRprime, A_Pt, A_Pa *Point
	// response
	Z_rbar, Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	CRangeProof *commitRange.ComRangeProof
	// common inputs
	BStar                                        *big.Int
	Fee                                          *big.Int
	CRStar                                       *Point
	C                                            *ElGamalEnc
	G, H, Ht, Ha, TDivCRprime, CLprimeInv, T, Pk *Point
	Challenge                                    *big.Int
}

func (proof *WithdrawProof) Bytes() []byte {
	res := make([]byte, WithdrawProofSize)
	copy(res[:PointSize], proof.Pt.Marshal())
	copy(res[PointSize:PointSize*2], proof.Pa.Marshal())
	copy(res[PointSize*2:PointSize*3], proof.A_pk.Marshal())
	copy(res[PointSize*3:PointSize*4], proof.A_TDivCRprime.Marshal())
	copy(res[PointSize*4:PointSize*5], proof.A_Pt.Marshal())
	copy(res[PointSize*5:PointSize*6], proof.A_Pa.Marshal())
	copy(res[PointSize*6:PointSize*7], proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*7:PointSize*8], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*8:PointSize*9], proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*9:PointSize*10], proof.CRStar.Marshal())
	C := proof.C.Bytes()
	copy(res[PointSize*10:PointSize*12], C[:])
	copy(res[PointSize*12:PointSize*13], proof.G.Marshal())
	copy(res[PointSize*13:PointSize*14], proof.H.Marshal())
	copy(res[PointSize*14:PointSize*15], proof.Ht.Marshal())
	copy(res[PointSize*15:PointSize*16], proof.Ha.Marshal())
	copy(res[PointSize*16:PointSize*17], proof.TDivCRprime.Marshal())
	copy(res[PointSize*17:PointSize*18], proof.CLprimeInv.Marshal())
	copy(res[PointSize*18:PointSize*19], proof.T.Marshal())
	copy(res[PointSize*19:PointSize*20], proof.Pk.Marshal())
	copy(res[PointSize*20:PointSize*21], proof.Challenge.FillBytes(make([]byte, PointSize)))
	copy(res[PointSize*21:PointSize*21+8], proof.BStar.FillBytes(make([]byte, 8)))
	copy(res[PointSize*21+8:PointSize*21+16], proof.Fee.FillBytes(make([]byte, 8)))
	copy(res[PointSize*21+16:], proof.CRangeProof.Bytes())
	return res
}

func (proof *WithdrawProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseWithdrawProofBytes(proofBytes []byte) (proof *WithdrawProof, err error) {
	if len(proofBytes) != WithdrawProofSize {
		return nil, ErrInvalidWithdrawProofSize
	}
	proof = new(WithdrawProof)
	proof.Pt, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.Pa, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.A_pk, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.A_TDivCRprime, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.A_Pt, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.A_Pa, err = curve.FromBytes(proofBytes[PointSize*5 : PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.Z_rbar = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	proof.Z_skInv = new(big.Int).SetBytes(proofBytes[PointSize*8 : PointSize*9])
	proof.CRStar, err = curve.FromBytes(proofBytes[PointSize*9 : PointSize*10])
	if err != nil {
		return nil, err
	}
	proof.C, err = twistedElgamal.FromBytes(proofBytes[PointSize*10 : PointSize*12])
	if err != nil {
		return nil, err
	}
	proof.G, err = curve.FromBytes(proofBytes[PointSize*12 : PointSize*13])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*13 : PointSize*14])
	if err != nil {
		return nil, err
	}
	proof.Ht, err = curve.FromBytes(proofBytes[PointSize*14 : PointSize*15])
	if err != nil {
		return nil, err
	}
	proof.Ha, err = curve.FromBytes(proofBytes[PointSize*15 : PointSize*16])
	if err != nil {
		return nil, err
	}
	proof.TDivCRprime, err = curve.FromBytes(proofBytes[PointSize*16 : PointSize*17])
	if err != nil {
		return nil, err
	}
	proof.CLprimeInv, err = curve.FromBytes(proofBytes[PointSize*17 : PointSize*18])
	if err != nil {
		return nil, err
	}
	proof.T, err = curve.FromBytes(proofBytes[PointSize*18 : PointSize*19])
	if err != nil {
		return nil, err
	}
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*19 : PointSize*20])
	if err != nil {
		return nil, err
	}
	proof.Challenge = new(big.Int).SetBytes(proofBytes[PointSize*20 : PointSize*21])
	proof.BStar = new(big.Int).SetBytes(proofBytes[PointSize*21 : PointSize*21+8])
	proof.Fee = new(big.Int).SetBytes(proofBytes[PointSize*21+8 : PointSize*21+16])
	proof.CRangeProof, err = commitRange.FromBytes(proofBytes[PointSize*21+16:])
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

func FakeWithdrawProof() *WithdrawProof {
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, _ := twistedElgamal.Enc(b, r, pk)
	bStar := big.NewInt(2)
	addr := "0x99AC8881834797ebC32f185ee27c2e96842e1a47"
	relation, _ := NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1, addr, big.NewInt(0))
	withdrawProof, _ := ProveWithdraw(relation)
	return withdrawProof
}

type WithdrawProofRelation struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CRStar *Point
	// new pedersen commitment for new balance
	T *Point
	// public key
	Pk *Point
	// Ht = h^{tid}
	Ht *Point
	// Pt = Ht^{sk}
	Pt *Point
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
	// T(C_R - C_R^{\Delta})^{-1}
	TDivCRprime *Point
	// (C_L - C_L^{\Delta})^{-1}
	CLprimeInv *Point
	// b^{\star}
	Bstar *big.Int
	// fee
	Fee *big.Int
	// ----------- private ---------------------
	Sk     *big.Int
	BPrime *big.Int
	RBar   *big.Int
	Rs     [RangeMaxBits]*big.Int
}

func NewWithdrawRelation(C *ElGamalEnc, pk *Point, b *big.Int, bStar *big.Int, sk *big.Int, tokenId uint32, receiveAddr string, fee *big.Int) (*WithdrawProofRelation, error) {
	if C == nil || pk == nil || bStar == nil || sk == nil  {
		return nil, ErrInvalidParams
	}
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	var (
		T      *Point
		bPrime *big.Int
		rBar   *big.Int
		rs     [RangeMaxBits]*big.Int
	)
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, ErrInsufficientBalance
	}
	if bStar.Cmp(Zero) < 0 {
		return nil, ErrPostiveBStar
	}
	if fee.Cmp(Zero) < 0 {
		return nil, ErrInvalidParams
	}
	// check if the b is correct
	hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
	hbCheck := curve.ScalarMul(H, b)
	if !hb.Equal(hbCheck) {
		return nil, ErrIncorrectBalance
	}
	// b' = b - b^{\star} - fee
	bPrime = ffmath.Sub(b, bStar)
	bPrime.Sub(bPrime, fee)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// C^{\Delta} = (pk^rStar,G^rStar h^{b^{\Delta} - fee})
	hNeg := curve.Neg(H)
	CRStar := curve.ScalarMul(hNeg, ffmath.Add(bStar, fee))
	// compute \bar{r} = \sum_{i=1}^32 r_i
	rBar = big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		rs[i] = curve.RandomValue()
		rBar.Add(rBar, rs[i])
	}
	rBar.Mod(rBar, Order)
	// T = g^{\bar{rStar}} h^{b'}
	T, err := pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	// compute Ha
	var addrBuf bytes.Buffer
	addrBuf.Write([]byte(receiveAddr))
	addrInt, err := util.HashToInt(addrBuf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	Ha := curve.ScalarMul(H, addrInt)
	relation := &WithdrawProofRelation{
		// ------------- public ---------------------
		C:           C,
		CRStar:      CRStar,
		T:           T,
		Pk:          pk,
		G:           G,
		H:           H,
		Ht:          curve.ScalarMul(H, big.NewInt(int64(tokenId))),
		Ha:          Ha,
		TokenId:     tokenId,
		TDivCRprime: curve.Add(T, curve.Neg(curve.Add(C.CR, CRStar))),
		CLprimeInv:  curve.Neg(C.CL),
		Bstar:       bStar,
		Fee:         fee,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
		Rs:     rs,
	}
	relation.Pt = curve.ScalarMul(relation.Ht, sk)
	relation.Pa = curve.ScalarMul(relation.Ha, sk)
	return relation, nil
}
