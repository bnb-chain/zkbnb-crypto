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
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type SwapProof struct {
	ProofPart1 *SwapProofPart
	ProofPart2 *SwapProofPart
}

func (proof *SwapProof) Bytes() []byte {
	proofBytes := make([]byte, SwapProofSize)
	copy(proofBytes[:SwapProofPartSize], proof.ProofPart1.Bytes())
	copy(proofBytes[SwapProofPartSize:], proof.ProofPart2.Bytes())
	return proofBytes
}

func (proof *SwapProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseSwapProofBytes(proofBytes []byte) (proof *SwapProof, err error) {
	if len(proofBytes) != SwapProofSize {
		return nil, ErrInvalidSwapProofSize
	}
	proof = new(SwapProof)
	proof.ProofPart1, err = ParseSwapProofPartBytes(proofBytes[:SwapProofPartSize])
	if err != nil {
		return nil, err
	}
	proof.ProofPart2, err = ParseSwapProofPartBytes(proofBytes[SwapProofPartSize:])
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ParseSwapProofStr(proofStr string) (*SwapProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseSwapProofBytes(proofBytes)
}

type SwapProofPart struct {
	// commitments
	Pt1                               *Point
	Pt2                               *Point
	A_pk, A_TDivCRprime, A_Pt1, A_Pt2 *Point
	// response
	Z_rbar, Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	RangeProof *commitRange.ComRangeProof
	// common inputs
	BStar1                                         *big.Int
	BStar2                                         *big.Int
	Fee                                            *big.Int
	RStar                                          *big.Int
	CStar                                          *ElGamalEnc
	C                                              *ElGamalEnc
	ReceiverCStar                                  *ElGamalEnc
	ReceiverC                                      *ElGamalEnc
	ReceiverPk                                     *Point
	G, H, Ht1, Ht2, TDivCRprime, CLprimeInv, T, Pk *Point
	Challenge                                      *big.Int
}

func (proof *SwapProofPart) Bytes() []byte {
	proofBytes := make([]byte, SwapProofPartSize)
	copy(proofBytes[:PointSize], proof.Pt1.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.Pt2.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.A_pk.Marshal())
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_TDivCRprime.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_Pt1.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.A_Pt2.Marshal())
	copy(proofBytes[PointSize*6:PointSize*7], proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*8:PointSize*9], proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*9:PointSize*10], proof.RStar.FillBytes(make([]byte, PointSize)))
	C := proof.C.Bytes()
	CStar := proof.CStar.Bytes()
	RecevierC := proof.ReceiverC.Bytes()
	ReceiverCStar := proof.ReceiverCStar.Bytes()
	copy(proofBytes[PointSize*10:PointSize*12], C[:])
	copy(proofBytes[PointSize*12:PointSize*14], CStar[:])
	copy(proofBytes[PointSize*14:PointSize*16], RecevierC[:])
	copy(proofBytes[PointSize*16:PointSize*18], ReceiverCStar[:])
	copy(proofBytes[PointSize*18:PointSize*19], proof.ReceiverPk.Marshal())
	// G, H, Ht1, Ht2, TDivCRprime, CLprimeInv, T, Pk
	copy(proofBytes[PointSize*19:PointSize*20], proof.G.Marshal())
	copy(proofBytes[PointSize*20:PointSize*21], proof.H.Marshal())
	copy(proofBytes[PointSize*21:PointSize*22], proof.Ht1.Marshal())
	copy(proofBytes[PointSize*22:PointSize*23], proof.Ht2.Marshal())
	copy(proofBytes[PointSize*23:PointSize*24], proof.TDivCRprime.Marshal())
	copy(proofBytes[PointSize*24:PointSize*25], proof.CLprimeInv.Marshal())
	copy(proofBytes[PointSize*25:PointSize*26], proof.T.Marshal())
	copy(proofBytes[PointSize*26:PointSize*27], proof.Pk.Marshal())
	copy(proofBytes[PointSize*27:PointSize*28], proof.Challenge.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*28:PointSize*28+8], proof.BStar1.FillBytes(make([]byte, 8)))
	copy(proofBytes[PointSize*28+8:PointSize*28+8*2], proof.BStar2.FillBytes(make([]byte, 8)))
	copy(proofBytes[PointSize*28+8*2:PointSize*28+8*3], proof.Fee.FillBytes(make([]byte, 8)))
	copy(proofBytes[PointSize*28+8*3:], proof.RangeProof.Bytes())
	return proofBytes
}

func (proof *SwapProofPart) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseSwapProofPartBytes(proofBytes []byte) (proof *SwapProofPart, err error) {
	if len(proofBytes) != SwapProofPartSize {
		return nil, ErrInvalidSwapProofPartSize
	}
	proof = new(SwapProofPart)
	proof.Pt1, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.Pt2, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
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
	proof.A_Pt1, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.A_Pt2, err = curve.FromBytes(proofBytes[PointSize*5 : PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.Z_rbar = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	proof.Z_skInv = new(big.Int).SetBytes(proofBytes[PointSize*8 : PointSize*9])
	proof.RStar = new(big.Int).SetBytes(proofBytes[PointSize*9 : PointSize*10])
	proof.C, err = twistedElgamal.FromBytes(proofBytes[PointSize*10 : PointSize*12])
	if err != nil {
		return nil, err
	}
	proof.CStar, err = twistedElgamal.FromBytes(proofBytes[PointSize*12 : PointSize*14])
	if err != nil {
		return nil, err
	}
	proof.ReceiverC, err = twistedElgamal.FromBytes(proofBytes[PointSize*14 : PointSize*16])
	if err != nil {
		return nil, err
	}
	proof.ReceiverCStar, err = twistedElgamal.FromBytes(proofBytes[PointSize*16 : PointSize*18])
	if err != nil {
		return nil, err
	}
	proof.ReceiverPk, err = curve.FromBytes(proofBytes[PointSize*18 : PointSize*19])
	if err != nil {
		return nil, err
	}
	proof.G, err = curve.FromBytes(proofBytes[PointSize*19 : PointSize*20])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*20 : PointSize*21])
	if err != nil {
		return nil, err
	}
	proof.Ht1, err = curve.FromBytes(proofBytes[PointSize*21 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.Ht2, err = curve.FromBytes(proofBytes[PointSize*22 : PointSize*23])
	if err != nil {
		return nil, err
	}
	proof.TDivCRprime, err = curve.FromBytes(proofBytes[PointSize*23 : PointSize*24])
	if err != nil {
		return nil, err
	}
	proof.CLprimeInv, err = curve.FromBytes(proofBytes[PointSize*24 : PointSize*25])
	if err != nil {
		return nil, err
	}
	proof.T, err = curve.FromBytes(proofBytes[PointSize*25 : PointSize*26])
	if err != nil {
		return nil, err
	}
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*26 : PointSize*27])
	if err != nil {
		return nil, err
	}
	proof.Challenge = new(big.Int).SetBytes(proofBytes[PointSize*27 : PointSize*28])
	proof.BStar1 = new(big.Int).SetBytes(proofBytes[PointSize*28 : PointSize*28+8])
	proof.BStar2 = new(big.Int).SetBytes(proofBytes[PointSize*28+8 : PointSize*28+8*2])
	proof.Fee = new(big.Int).SetBytes(proofBytes[PointSize*28+8*2 : PointSize*28+8*3])
	proof.RangeProof, err = commitRange.FromBytes(proofBytes[PointSize*28+8*3:])
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ParseSwapProofPartStr(proofStr string) (*SwapProofPart, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseSwapProofPartBytes(proofBytes)
}

type SwapProofRelationPart struct {
	// ------------- public ---------------------
	// from original balance enc
	C *ElGamalEnc
	// from delta balance enc
	CStar *ElGamalEnc
	// to original balance enc
	ReceiverC *ElGamalEnc
	// to delta balance enc
	ReceiverCStar *ElGamalEnc
	// to public key
	ReceiverPk *Point
	// from: new pedersen commitment for new balance
	T *Point
	// from: public key
	Pk *Point
	// HtFrom = h^{tid}
	Ht1 *Point
	// HtTo = h^{tid}
	Ht2 *Point
	// PtFrom1 = HtFrom^{sk_a}
	Pt1 *Point
	// PtFrom2 = HtTo^{sk_a}
	Pt2 *Point
	// generator 1
	G *Point
	// generator 2
	H *Point
	// from token Id
	FromTokenId uint32
	// to token Id
	ToTokenId uint32
	// T(C_R - C_R^{\Delta})^{-1}
	TDivCRprime *Point
	// (C_L - C_L^{\Delta})^{-1}
	CLprimeInv *Point
	// b^{\star}
	BStarFrom *big.Int
	BStarTo   *big.Int
	Fee       *big.Int
	// r^{\star}
	RStar *big.Int
	// ----------- private ---------------------
	Sk     *big.Int
	BPrime *big.Int
	RBar   *big.Int
	Rs     [RangeMaxBits]*big.Int
}

func NewSwapRelationPart1(C, receiverC *ElGamalEnc, pk, receiverPk *Point, b, bStarFrom, bStarTo *big.Int, sk *big.Int, fromTokenId, toTokenId uint32, fee *big.Int) (*SwapProofRelationPart, error) {
	if C == nil || receiverC == nil || pk == nil || receiverPk == nil || bStarFrom == nil || bStarTo == nil || sk == nil || fromTokenId == 0 || toTokenId == 0 || fromTokenId == toTokenId || fee == nil || fee.Cmp(Zero) < 0 {
		return nil, ErrInvalidParams
	}
	// check if the public key is valid
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	var (
		T      *Point
		bPrime *big.Int
		rStar  *big.Int
		rBar   *big.Int
		CStar  *ElGamalEnc
		rs     [RangeMaxBits]*big.Int
	)
	// check if the b is correct
	hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
	hbCheck := curve.ScalarMul(H, b)
	if !hb.Equal(hbCheck) {
		return nil, ErrIncorrectBalance
	}
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, ErrInsufficientBalance
	}
	if bStarFrom.Cmp(Zero) <= 0 {
		return nil, ErrPostiveBStar
	}
	// b' = b - b^{\star} - fee
	bPrime = ffmath.Sub(b, bStarFrom)
	bPrime.Sub(bPrime, fee)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// C^{\star} = (pk^rStar,G^rStar h^{b^{\star}})
	deltaBalance := ffmath.Add(bStarFrom, fee)
	rStar = curve.RandomValue()
	CStar, err := twistedElgamal.Enc(ffmath.Neg(deltaBalance), rStar, pk)
	if err != nil {
		return nil, err
	}
	receiverCStar, err := twistedElgamal.Enc(deltaBalance, rStar, receiverPk)
	if err != nil {
		return nil, err
	}
	// \bar{rStar} \gets_R Z_p
	rBar = big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		rs[i] = curve.RandomValue()
		rBar.Add(rBar, rs[i])
	}
	rBar.Mod(rBar, Order)
	// T = g^{\bar{rStar}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &SwapProofRelationPart{
		// ------------- public ---------------------
		C:             C,
		CStar:         CStar,
		ReceiverC:     receiverC,
		ReceiverCStar: receiverCStar,
		ReceiverPk:    receiverPk,
		T:             T,
		Pk:            pk,
		G:             G,
		H:             H,
		Ht1:           curve.ScalarMul(H, big.NewInt(int64(fromTokenId))),
		Ht2:           curve.ScalarMul(H, big.NewInt(int64(toTokenId))),
		FromTokenId:   fromTokenId,
		ToTokenId:     toTokenId,
		TDivCRprime:   curve.Add(T, curve.Neg(curve.Add(C.CR, CStar.CR))),
		CLprimeInv:    curve.Neg(curve.Add(C.CL, CStar.CL)),
		BStarFrom:     bStarFrom,
		BStarTo:       bStarTo,
		Fee:           fee,
		RStar:         rStar,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
		Rs:     rs,
	}
	relation.Pt1 = curve.ScalarMul(relation.Ht1, sk)
	relation.Pt2 = curve.ScalarMul(relation.Ht2, sk)

	return relation, nil
}

func NewSwapRelationPart2(C, receiverC *ElGamalEnc, pk, receiverPk *Point, b, sk *big.Int, fromTokenId, toTokenId uint32, proof *SwapProofPart) (*SwapProofRelationPart, error) {
	if C == nil || receiverC == nil || pk == nil || receiverPk == nil || sk == nil || proof == nil || fromTokenId == 0 ||
		toTokenId == 0 || fromTokenId == toTokenId || proof.Ht1 == nil ||
		proof.Ht2 == nil || proof.BStar1.Cmp(big.NewInt(0)) <= 0 || proof.BStar2.Cmp(big.NewInt(0)) <= 0 {
		return nil, ErrInvalidParams
	}
	// check if the public key is valid
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	Ht1 := curve.ScalarMul(H, big.NewInt(int64(fromTokenId)))
	Ht2 := curve.ScalarMul(H, big.NewInt(int64(toTokenId)))
	if !Ht1.Equal(proof.Ht1) || !Ht2.Equal(proof.Ht2) {
		return nil, ErrInvalidSwapProof
	}
	var (
		T      *Point
		bPrime *big.Int
		rStar  *big.Int
		rBar   *big.Int
		CStar  *ElGamalEnc
		rs     [RangeMaxBits]*big.Int
	)
	// check if the b is correct
	hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
	hbCheck := curve.ScalarMul(H, b)
	if !hb.Equal(hbCheck) {
		return nil, ErrIncorrectBalance
	}
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, ErrInsufficientBalance
	}
	if proof.BStar2.Cmp(Zero) <= 0 {
		return nil, ErrPostiveBStar
	}
	// b' = b - b^{\star}
	bPrime = ffmath.Sub(b, proof.BStar2)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// C^{\Delta} = (pk^rStar,G^rStar h^{b^{\Delta}})
	rStar = curve.RandomValue()
	CStar, err := twistedElgamal.Enc(new(big.Int).Neg(proof.BStar2), rStar, pk)
	if err != nil {
		return nil, err
	}
	receiverCStar, err := twistedElgamal.Enc(proof.BStar2, rStar, receiverPk)
	if err != nil {
		return nil, err
	}
	// \bar{rStar} \gets_R Z_p
	rBar = big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		rs[i] = curve.RandomValue()
		rBar.Add(rBar, rs[i])
	}
	rBar.Mod(rBar, Order)
	// T = g^{\bar{rStar}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &SwapProofRelationPart{
		// ------------- public ---------------------
		C:             C,
		CStar:         CStar,
		ReceiverC:     receiverC,
		ReceiverCStar: receiverCStar,
		ReceiverPk:    receiverPk,
		T:             T,
		Pk:            pk,
		G:             G,
		H:             H,
		Ht1:           Ht1,
		Ht2:           Ht2,
		FromTokenId:   fromTokenId,
		ToTokenId:     toTokenId,
		TDivCRprime:   curve.Add(T, curve.Neg(curve.Add(C.CR, CStar.CR))),
		CLprimeInv:    curve.Neg(curve.Add(C.CL, CStar.CL)),
		BStarFrom:     proof.BStar1,
		BStarTo:       proof.BStar2,
		Fee:           proof.Fee,
		RStar:         rStar,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
		Rs:     rs,
	}
	relation.Pt1 = curve.ScalarMul(relation.Ht1, sk)
	relation.Pt2 = curve.ScalarMul(relation.Ht2, sk)

	return relation, nil
}

func FakeSwapProof() *SwapProof {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	bEnc1, _ := twistedElgamal.Enc(b1, r1, pk1)
	sk2, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(3)
	r2 := curve.RandomValue()
	bEnc2, _ := twistedElgamal.Enc(b2, r2, pk2)
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
	relationPart1, _ := NewSwapRelationPart1(bEnc1, bEnc2, pk1, pk2, b1, bStarFrom, bStarTo, sk1, fromTokenId, toTokenId, big.NewInt(0))
	swapProofPart1, _ := ProveSwapPart1(relationPart1, true)
	b3 := big.NewInt(8)
	r3 := curve.RandomValue()
	bEnc3, _ := twistedElgamal.Enc(b3, r3, pk2)
	b4 := big.NewInt(8)
	r4 := curve.RandomValue()
	bEnc4, _ := twistedElgamal.Enc(b4, r4, pk1)
	relationPart2, _ := NewSwapRelationPart2(bEnc3, bEnc4, pk2, pk1, b3, sk2, fromTokenId, toTokenId, swapProofPart1)
	swapProof, _ := ProveSwapPart2(relationPart2, swapProofPart1)
	return swapProof
}
