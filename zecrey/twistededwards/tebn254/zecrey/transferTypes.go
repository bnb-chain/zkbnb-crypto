package zecrey

import (
	"math/big"
)

type RangeProofParams struct {
	*BPSetupParams
}

type PTransferProof struct {
}

type PTransferProofRelation struct {
	Statements []*PTransferProofStatement
	G          *Point
	H          *Point
	Order      *big.Int
}

func NewPTransferProofRelation() *PTransferProofRelation {
	return &PTransferProofRelation{G: G, H: H, Order: Order}
}

func (relation *PTransferProofRelation) AddStatement(C *ElGamalEnc, pk *Point, b *big.Int, bDelta *big.Int, sk *big.Int, tokenId uint32) error {
	
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
