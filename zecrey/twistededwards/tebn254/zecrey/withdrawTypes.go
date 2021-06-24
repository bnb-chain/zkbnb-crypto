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

type WithdrawProof struct {
	// commitments
	Pt                        *Point
	A_pk, A_TDivCRprime, A_Pt *Point
	// response
	Z_rbar, Z_sk, Z_skInv *big.Int
	// Commitment Range Proofs
	CRangeProof *commitRange.ComRangeProof
	// common inputs
	BStar                                    *big.Int
	CRStar                                   *Point
	C                                        *ElGamalEnc
	G, H, Ht, TDivCRprime, CLprimeInv, T, Pk *Point
	Challenge                                *big.Int
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
	// ----------- private ---------------------
	Sk     *big.Int
	BPrime *big.Int
	RBar   *big.Int
}

func NewWithdrawRelation(C *ElGamalEnc, pk *Point, bStar *big.Int, sk *big.Int, tokenId uint32) (*WithdrawProofRelation, error) {
	if C == nil || pk == nil || bStar == nil || sk == nil || tokenId == 0 {
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
	if bStar.Cmp(Zero) >= 0 {
		return nil, ErrNegativeBStar
	}
	// b' = b + b^{\star}
	bPrime = ffmath.Add(b, bStar)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// C^{\Delta} = (pk^rStar,G^rStar h^{b^{\Delta}})
	CRStar := curve.ScalarMul(H, bStar)
	// \bar{rStar} \gets_R Z_p
	rBar = curve.RandomValue()
	// T = g^{\bar{rStar}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &WithdrawProofRelation{
		// ------------- public ---------------------
		C:           C,
		CRStar:      CRStar,
		T:           T,
		Pk:          pk,
		G:           G,
		H:           H,
		Ht:          curve.ScalarMul(H, big.NewInt(int64(tokenId))),
		TokenId:     tokenId,
		TDivCRprime: curve.Add(T, curve.Neg(curve.Add(C.CR, CRStar))),
		CLprimeInv:  curve.Neg(C.CL),
		Bstar:       bStar,
		// ----------- private ---------------------
		Sk:     sk,
		BPrime: bPrime,
		RBar:   rBar,
	}
	relation.Pt = curve.ScalarMul(relation.Ht, sk)
	return relation, nil
}
