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
	Pt                                            *Point
	A_CLStar, A_CRStar, A_pk, A_TDivCRprime, A_Pt *Point
	// response
	z_r, z_bDelta, z_rbar, z_sk, z_skInv *big.Int
	// Commitment Range Proofs
	CRangeProofs []*commitRange.ComRangeProof
	// common inputs
	C, CStar                                 *ElGamalEnc
	G, H, Ht, TDivCRprime, CLprimeInv, T, Pk *Point
	Challenge                                *big.Int
}

type WithdrawProofRelation struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CStar *ElGamalEnc
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
	BStar *big.Int
	// ----------- private ---------------------
	Sk     *big.Int
	R      *big.Int
	BPrime *big.Int
	RBar   *big.Int
}

func NewWithdrawRelation(C *ElGamalEnc, pk *Point, b *big.Int, bStar *big.Int, sk *big.Int, tokenId uint32) (*WithdrawProofRelation, error) {
	if C == nil || pk == nil || b == nil || bStar == nil || sk == nil || tokenId == 0 {
		return nil, ErrInvalidParams
	}
	oriPk := curve.ScalarBaseMul(sk)
	if !oriPk.Equal(pk) {
		return nil, ErrInconsistentPublicKey
	}
	var (
		CStar  *ElGamalEnc
		T      *Point
		bPrime *big.Int
		r      *big.Int
		rBar   *big.Int
	)
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, ErrInsufficientBalance
	}
	if bStar.Cmp(Zero) <= 0 {
		return nil, ErrNegativeBStar
	}
	// b' = b - b^{\star}
	bPrime = ffmath.Sub(b, bStar)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, ErrInsufficientBalance
	}
	// r \gets_R Z_p
	r = curve.RandomValue()
	// C^{\Delta} = (pk^r,G^r h^{b^{\Delta}})
	CStar, err := twistedElgamal.Enc(bStar, r, pk)
	if err != nil {
		return nil, err
	}
	// \bar{r} \gets_R Z_p
	rBar = curve.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return nil, err
	}
	relation := &WithdrawProofRelation{
		// ------------- public ---------------------
		C:           C,
		CStar:       CStar,
		T:           T,
		Pk:          pk,
		G:           G,
		H:           H,
		Ht:          curve.ScalarMul(H, big.NewInt(int64(tokenId))),
		TokenId:     tokenId,
		TDivCRprime: curve.Add(T, curve.Neg(curve.Add(C.CR, curve.Neg(CStar.CR)))),
		CLprimeInv:  curve.Neg(curve.Add(C.CL, curve.Neg(CStar.CL))),
		BStar:       bStar,
		// ----------- private ---------------------
		Sk:     sk,
		R:      r,
		BPrime: bPrime,
		RBar:   rBar,
	}
	relation.Pt = curve.ScalarMul(relation.Ht, sk)
	return relation, nil
}
