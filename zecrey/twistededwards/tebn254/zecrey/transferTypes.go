package zecrey

import (
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type PTransferProof struct {
	// sub proofs
	SubProofs []*PTransferSubProof
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum *Point
	// A_Pt
	A_Pts []*Point
	// z_tsk
	Z_tsks []*big.Int
	// Pt = (Ht)^{sk_i}
	Pts []*Point
	// challenges
	C1, C2   *big.Int
	G, H, Ht *Point
	Fee      *big.Int
}

type PTransferSubProof struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime *Point
	// respond values
	Z_r, Z_bDelta, Z_rstarSubr, Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv *big.Int
	// range proof
	CRangeProof *commitRange.ComRangeProof
	// common inputs
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *Point
	// new pedersen commitment for deleta balance or new balance
	Y *Point
	// public key
	Pk *Point
	// T (C_R + C_R^{\Delta})^{-1}
	TCRprimeInv *Point
	// (C_L + C_L^{\Delta})^{-1}
	CLprimeInv *Point
}

type PTransferProofRelation struct {
	Statements []*PTransferProofStatement
	Fee        *big.Int
	G          *Point
	H          *Point
	Ht         *Point
	Pts        []*Point
	TokenId    uint32
}

func NewPTransferProofRelation(tokenId uint32, fee *big.Int) (*PTransferProofRelation, error) {
	if tokenId == 0 {
		return nil, ErrInvalidParams
	}
	if fee.Cmp(Zero) < 0 {
		return nil, ErrInvalidParams
	}
	Ht := curve.ScalarMul(H, big.NewInt(int64(tokenId)))
	return &PTransferProofRelation{G: G, H: H, Ht: Ht, TokenId: tokenId, Fee: fee}, nil
}

func (relation *PTransferProofRelation) AddStatement(C *ElGamalEnc, pk *Point, b *big.Int, bDelta *big.Int, sk *big.Int) (err error) {
	// check params
	if C == nil || pk == nil {
		return ErrInvalidParams
	}
	// if the user owns the account, should do more verifications
	if sk != nil {
		oriPk := curve.ScalarBaseMul(sk)
		// 1. should be the same public key
		// 2. b should not be null and larger than zero
		// 3. bDelta should smaller than zero
		if !oriPk.Equal(pk) {
			return ErrInconsistentPublicKey
		}
		// check if the b is correct
		hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
		hbCheck := curve.ScalarMul(H, b)
		if !hb.Equal(hbCheck) {
			return ErrIncorrectBalance
		}
		if b == nil || b.Cmp(Zero) < 0 {
			return ErrInsufficientBalance
		}
		if bDelta.Cmp(Zero) > 0 {
			return ErrInvalidDelta
		}
		// add Pt
		Pt := curve.ScalarMul(relation.Ht, sk)
		relation.Pts = append(relation.Pts, Pt)
	}
	// now b != nil
	var (
		CDelta *ElGamalEnc
		T      *Point
		Y      *Point
		bPrime *big.Int
		bStar  *big.Int
		r      *big.Int
		rBar   *big.Int
		rStar  *big.Int
		rs     [RangeMaxBits]*big.Int
	)
	// if user knows b which means that he owns the account
	if b != nil && sk != nil {
		// b' = b + b^{\Delta}
		bPrime = ffmath.Add(b, bDelta)
		// bPrime should bigger than zero
		if bPrime.Cmp(Zero) < 0 {
			return ErrInsufficientBalance
		}
		bStar = bPrime
	} else {
		bStar = bDelta
		bPrime = PadSecret
	}
	// r \gets_R \mathbb{Z}_p
	r = curve.RandomValue()
	// C^{\Delta} = (pk^r, g^r h^{b^{\Delta}})
	CDelta, err = twistedElgamal.Enc(bDelta, r, pk)
	if err != nil {
		return err
	}
	// r^{\star} \gets_R \mathbb{Z}_p
	rStar = big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		rs[i] = curve.RandomValue()
		rStar.Add(rStar, rs[i])
	}
	rStar.Mod(rStar, Order)
	// \bar{r} \gets_R \mathbb{Z}_p
	rBar = curve.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return err
	}
	Y, err = pedersen.Commit(rStar, bStar, G, H)
	if err != nil {
		return err
	}
	// create statement
	statement := &PTransferProofStatement{
		// ------------- public ---------------------
		C:           C,
		CDelta:      CDelta,
		T:           T,
		Y:           Y,
		Pk:          pk,
		TCRprimeInv: curve.Add(T, curve.Neg(curve.Add(C.CR, CDelta.CR))),
		CLprimeInv:  curve.Neg(curve.Add(C.CL, CDelta.CL)),
		// ----------- private ---------------------
		BDelta: bDelta,
		BStar:  bStar,
		BPrime: bPrime,
		Sk:     sk,
		R:      r,
		RBar:   rBar,
		RStar:  rStar,
		Rs:     rs,
	}
	relation.Statements = append(relation.Statements, statement)
	return nil
}

type PTransferProofStatement struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *Point
	// new pedersen commitment for deleta balance or new balance
	Y *Point
	// public key
	Pk *Point
	// T (C_R + C_R^{\Delta})^{-1}
	TCRprimeInv *Point
	// (C_L + C_L^{\Delta})^{-1}
	CLprimeInv *Point
	// ----------- private ---------------------
	// delta balance
	BDelta *big.Int
	// copy for delta balance or new balance
	BStar *big.Int
	// new balance
	BPrime *big.Int
	// private key
	Sk *big.Int
	// random value for CDelta
	R *big.Int
	// random value for T
	RBar *big.Int
	// random value for Y
	RStar *big.Int
	// rs
	Rs [RangeMaxBits]*big.Int
	// token id
	TokenId uint32
}

type transferCommitValues struct {
	// random values
	alpha_r, alpha_bDelta, alpha_rstarSubr,
	alpha_rstarSubrbar, alpha_rbar, alpha_bprime,
	alpha_sk, alpha_skInv *big.Int
	// commit
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT,
	A_T, A_pk, A_TDivCPrime *Point
}

func FakeTransferProof() *PTransferProof {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, _ := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, _ := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, _ := twistedElgamal.Enc(b3, r3, pk3)
	relation, _ := NewPTransferProofRelation(1, big.NewInt(0))
	relation.AddStatement(b2Enc, pk2, nil, big.NewInt(2), nil)
	relation.AddStatement(b1Enc, pk1, b1, big.NewInt(-4), sk1)
	relation.AddStatement(b3Enc, pk3, b3, big.NewInt(2), nil)
	transferProof, _ := ProvePTransfer(relation)
	return transferProof
}
