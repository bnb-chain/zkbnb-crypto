package zecrey

import (
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/bulletProofs"
)

type ZSetupParams struct {
	*BPSetupParams
}

func Setup(N, M int64) (*ZSetupParams, error) {
	bpSetupParams, err := bulletProofs.Setup(N, M)
	if err != nil {
		return nil, err
	}
	return &ZSetupParams{bpSetupParams}, nil
}

type PTransferProof struct {
	// sub proofs
	SubProofs []*PTransferSubProof
	// BP Proof
	BPProof *AggBulletProof
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
}

type PTransferSubProof struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime *Point
	// respond values
	z_r, z_bDelta, z_rstarSubr, z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv *big.Int
	// common statements
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
	G          *Point
	H          *Point
	Ht         *Point
	Pts        []*Point
	Order      *big.Int
	TokenId    uint32
}

func NewPTransferProofRelation(tokenId uint32) (*PTransferProofRelation, error) {
	if tokenId == 0 {
		return nil, ErrInvalidParams
	}
	Ht := curve.ScalarBaseMul(big.NewInt(int64(tokenId)))
	return &PTransferProofRelation{G: G, H: H, Order: Order, Ht: Ht, TokenId: tokenId}, nil
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
		// 3. bDelta should larger than zero
		if !oriPk.Equal(pk) {
			return ErrInconsistentPublicKey
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
	)
	// if user knows b which means that he owns the account
	if b != nil {
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
	rStar = curve.RandomValue()
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
