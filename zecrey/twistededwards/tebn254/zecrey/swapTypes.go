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
	RStar                                          *big.Int
	CStar                                          *ElGamalEnc
	C                                              *ElGamalEnc
	G, H, Ht1, Ht2, TDivCRprime, CLprimeInv, T, Pk *Point
	Challenge                                      *big.Int
}

type SwapProofRelationPart struct {
	// ------------- public ---------------------
	// from original balance enc
	C *ElGamalEnc
	// from delta balance enc
	CStar *ElGamalEnc
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
	// r^{\star}
	RStar *big.Int
	// ----------- private ---------------------
	Sk     *big.Int
	BPrime *big.Int
	RBar   *big.Int
}

func NewSwapRelationPart1(C *ElGamalEnc, pk *Point, bStarFrom, bStarTo *big.Int, sk *big.Int, fromTokenId, toTokenId uint32) (*SwapProofRelationPart, error) {
	if C == nil || pk == nil || bStarFrom == nil || bStarTo == nil || sk == nil || fromTokenId == 0 || toTokenId == 0 || fromTokenId == toTokenId {
		return nil, ErrInvalidParams
	}
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
	)
	// compute b first
	b, err := twistedElgamal.Dec(C, sk, Max)
	if err != nil {
		return nil, ErrInvalidParams
	}
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, ErrInsufficientBalance
	}
	if bStarFrom.Cmp(Zero) <= 0 {
		return nil, ErrPostiveBStar
	}
	// b' = b - b^{\star}
	bPrime = ffmath.Sub(b, bStarFrom)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// C^{\star} = (pk^rStar,G^rStar h^{b^{\star}})
	rStar = curve.RandomValue()
	CStar, err = twistedElgamal.Enc(new(big.Int).Neg(bStarFrom), rStar, pk)
	if err != nil {
		return nil, err
	}
	// \bar{rStar} \gets_R Z_p
	rBar = curve.RandomValue()
	// T = g^{\bar{rStar}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &SwapProofRelationPart{
		// ------------- public ---------------------
		C:           C,
		CStar:       CStar,
		T:           T,
		Pk:          pk,
		G:           G,
		H:           H,
		Ht1:         curve.ScalarMul(H, big.NewInt(int64(fromTokenId))),
		Ht2:         curve.ScalarMul(H, big.NewInt(int64(toTokenId))),
		FromTokenId: fromTokenId,
		ToTokenId:   toTokenId,
		TDivCRprime: curve.Add(T, curve.Neg(curve.Add(C.CR, CStar.CR))),
		CLprimeInv:  curve.Neg(curve.Add(C.CL, CStar.CL)),
		BStarFrom:   bStarFrom,
		BStarTo:     bStarTo,
		RStar:       rStar,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
	}
	relation.Pt1 = curve.ScalarMul(relation.Ht1, sk)
	relation.Pt2 = curve.ScalarMul(relation.Ht2, sk)

	return relation, nil
}

func NewSwapRelationPart2(C *ElGamalEnc, pk *Point, sk *big.Int, fromTokenId, toTokenId uint32, proof *SwapProofPart) (*SwapProofRelationPart, error) {
	if C == nil || pk == nil || sk == nil || proof == nil || fromTokenId == 0 ||
		toTokenId == 0 || fromTokenId == toTokenId || proof.Ht1 == nil ||
		proof.Ht2 == nil || proof.BStar1.Cmp(big.NewInt(0)) <= 0 || proof.BStar2.Cmp(big.NewInt(0)) <= 0 {
		return nil, ErrInvalidParams
	}
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
	)
	// compute b first
	b, err := twistedElgamal.Dec(C, sk, Max)
	if err != nil {
		return nil, ErrInvalidParams
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
	CStar, err = twistedElgamal.Enc(new(big.Int).Neg(proof.BStar2), rStar, pk)
	if err != nil {
		return nil, err
	}
	// \bar{rStar} \gets_R Z_p
	rBar = curve.RandomValue()
	// T = g^{\bar{rStar}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &SwapProofRelationPart{
		// ------------- public ---------------------
		C:           C,
		CStar:       CStar,
		T:           T,
		Pk:          pk,
		G:           G,
		H:           H,
		Ht1:         Ht1,
		Ht2:         Ht2,
		FromTokenId: fromTokenId,
		ToTokenId:   toTokenId,
		TDivCRprime: curve.Add(T, curve.Neg(curve.Add(C.CR, CStar.CR))),
		CLprimeInv:  curve.Neg(curve.Add(C.CL, CStar.CL)),
		BStarFrom:   proof.BStar1,
		BStarTo:     proof.BStar2,
		RStar:       rStar,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
	}
	relation.Pt1 = curve.ScalarMul(relation.Ht1, sk)
	relation.Pt2 = curve.ScalarMul(relation.Ht2, sk)

	return relation, nil
}
