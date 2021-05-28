package zecrey

import (
	"math/big"
	"zecrey-crypto/commitment/secp256k1/pedersen"
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/elgamal/secp256k1/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/secp256k1/bulletProofs"
)

type (
	ElGamalEnc = twistedElgamal.ElGamalEnc
	BulletProofSetupParams = bulletProofs.BulletProofSetupParams
	BulletProof = bulletProofs.BulletProof
	P256 = zp256.P256
)

type TransferParams struct {
	*BulletProofSetupParams
}

type ZKSneakTransferProof struct {
	EncProofs   []*AnonEncProof
	RangeProofs []*AnonRangeProof
	EqualProof  *AnonEqualProof
}

type AnonEncProof struct {
	Z *big.Int
	A *P256
	R *P256
	G *P256
}

type AnonRangeProof struct {
	RangeProof *BulletProof
	SkProof    *ChaumPedersenProof
}

type ChaumPedersenProof struct {
	Z      *big.Int
	G, U   *P256
	Vt, Wt *P256
	V, W   *P256
}

type AnonEqualProof struct {
	ZArr  []*big.Int
	UtArr []*P256
	GArr  []*P256
	UArr  []*P256
}

type TransferProofStatement struct {
	Relations []*TransferProofRelation
	G         *P256
	H         *P256
	// TODO GEpoch maybe delete
	GEpoch *P256
	Ws     []*P256
}

func NewTransferStatement() *TransferProofStatement {
	// TODO GEpoch
	return &TransferProofStatement{G: G, H: H}
}

func (statement *TransferProofStatement) AddRelation(C *ElGamalEnc, pk *P256, b *big.Int, bDelta *big.Int, sk *big.Int, tokenId uint32) error {
	// check sk
	if sk != nil {
		// check public key is consistent
		oriPk := zp256.ScalarBaseMul(sk)
		if !zp256.Equal(oriPk, pk) {
			return InconsistentPublicKey
		}
	}

	var (
		CDelta *ElGamalEnc
		T      *P256
		Y      *P256
		bPrime *big.Int
		bStar  *big.Int
		r      *big.Int
		rBar   *big.Int
		rStar  *big.Int
	)

	// check balance
	if b.Cmp(Zero) <= 0 {
		return InvalidBalance
	}
	// check bDelta and b
	if bDelta.Cmp(Zero) < 0 && b == nil {
		return InvalidOwnership
	}
	// if user knows b which means that he owns the account
	if b != nil {
		// b' = b - b^{\Delta}
		bPrime = ffmath.Add(b, bDelta)
		// bPrime should bigger than zero
		if bPrime.Cmp(Zero) < 0 {
			return InsufficientBalance
		}
		bStar = bPrime
	} else {
		bStar = bDelta
	}
	// r \gets_R Z_p
	r = zp256.RandomValue()
	// C^{\Delta} = (pk^r,G^r h^{b^{\Delta}})
	CDelta = twistedElgamal.Enc(bDelta, r, pk)
	// r^{\star} \gets_R Z_p
	rStar = zp256.RandomValue()
	// Y = g^{r^{\star}} h^{b}
	Y = pedersen.Commit(rStar, bStar, G, H)
	// \bar{r} \gets_R Z_p
	rBar = zp256.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T = pedersen.Commit(rBar, bPrime, G, H)

	// create relation
	relation := &TransferProofRelation{
		// ------------- public ---------------------
		C:      C,
		CDelta: CDelta,
		T:      T,
		Y:      Y,
		Pk:     pk,
		// ----------- private ---------------------
		BDelta:  bDelta,
		BStar:   bStar,
		BPrime:  bPrime,
		Sk:      sk,
		R:       r,
		RBar:    rBar,
		RStar:   rStar,
		TokenId: tokenId,
	}
	statement.Relations = append(statement.Relations, relation)
	return nil
}

type TransferProofRelation struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *P256
	// new pedersen commitment for deleta balance or new balance
	Y *P256
	// public key
	Pk *P256
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
	// TODO chain & token
	TokenId uint32
}

type WithdrawProofStatement struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *P256
	// public key
	Pk *P256
	// ----------- private ---------------------
	Sk     *big.Int
	R      *big.Int
	BPrime *big.Int
	RBar   *big.Int
	G      *P256
	H      *P256
	// TODO GEpoch maybe delete
	GEpoch  *P256
	W       *P256
	TokenId uint32
}

func NewWithdrawStatement(C *ElGamalEnc, pk *P256, b *big.Int, bDelta *big.Int, sk *big.Int, tokenId uint32) (*WithdrawProofStatement, error) {
	if C == nil || pk == nil || b == nil || bDelta == nil || sk == nil || tokenId == 0 {
		return nil, InvalidParams
	}
	oriPk := zp256.ScalarBaseMul(sk)
	if !zp256.Equal(oriPk, pk) {
		return nil, InconsistentPublicKey
	}
	var (
		CDelta *ElGamalEnc
		T      *P256
		bPrime *big.Int
		r      *big.Int
		rBar   *big.Int
	)
	// check balance
	if b.Cmp(Zero) <= 0 {
		return nil, InvalidBalance
	}
	// b' = b - b^{\Delta}
	bPrime = ffmath.Add(b, bDelta)
	// bPrime should bigger than zero
	if bPrime.Cmp(Zero) < 0 {
		return nil, InsufficientBalance
	}
	// r \gets_R Z_p
	r = zp256.RandomValue()
	// C^{\Delta} = (pk^r,G^r h^{b^{\Delta}})
	CDelta = twistedElgamal.Enc(bDelta, r, pk)
	// \bar{r} \gets_R Z_p
	rBar = zp256.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T = pedersen.Commit(rBar, bPrime, G, H)
	// TODO GEpoch
	return &WithdrawProofStatement{
		// ------------- public ---------------------
		C:      C,
		CDelta: CDelta,
		T:      T,
		Pk:     pk,
		// ----------- private ---------------------
		Sk:      sk,
		R:       r,
		BPrime:  bPrime,
		RBar:    rBar,
		G:       G,
		H:       H,
		TokenId: tokenId,
	}, nil
}
