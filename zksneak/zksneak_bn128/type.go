package zksneak

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak/ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ZKSneakStatement struct {
	Relations []*ZKSneakRelation
	RStar     *big.Int
}

func NewStatement() *ZKSneakStatement {
}

func (statement *ZKSneakStatement) AddRelation(C *twistedElgamal_bn128.ElGamalEnc, pk *bn256.G1Affine, b *big.Int, bDelta *big.Int) {
	
}

type ZKSneakRelation struct {
	// public
	CPrime *twistedElgamal_bn128.ElGamalEnc
	// public
	CTilde *twistedElgamal_bn128.ElGamalEnc
	// public
	CDelta *twistedElgamal_bn128.ElGamalEnc
	// public
	Pk *bn256.G1Affine
	// secret
	BDelta *big.Int
	// secret
	BPrime *big.Int
	// secret
	Sk *big.Int
	// secret
	R *big.Int
}

type ZKSneakParams struct {
	G        *bn256.G1Affine
	H        *bn256.G1Affine
	BPParams *BulletProofsParams
}

type BulletProofsParams struct {
	// N is the bit-length of the range.
	N int64
	// Gg and Hh are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gg []*bn256.G1Affine
	Hh []*bn256.G1Affine
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams bp_bn128.InnerProductParams
}
