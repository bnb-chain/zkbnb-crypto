package zksneak_bn128

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"crypto/rand"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type (
	ElGamalEnc = twistedElgamal_bn128.ElGamalEnc
	BulletProofSetupParams = bp_bn128.BulletProofSetupParams
	BulletProof = bp_bn128.BulletProof
)

type ZKSneakTransferProof struct {
	EncProofs   []*AnonEncProof
	RangeProofs []*AnonRangeProof
	EqualProof  *AnonEqualProof
}

type AnonEncProof struct {
	z *big.Int
	A *bn256.G1Affine
	R *bn256.G1Affine
	g *bn256.G1Affine
}

type AnonRangeProof struct {
	RangeProof *BulletProof
	SkProof    *ChaumPedersenProof
}

type ChaumPedersenProof struct {
	z      *big.Int
	g, u   *bn256.G1Affine
	Vt, Wt *bn256.G1Affine
	v, w   *bn256.G1Affine
}

type AnonEqualProof struct {
	zArr  []*big.Int
	UtArr []*bn256.G1Affine
	gArr  []*bn256.G1Affine
	uArr  []*bn256.G1Affine
}

type ZKSneakTransferStatement struct {
	Relations []*ZKSneakTransferRelation
	rStar     *big.Int
}

func NewStatement() *ZKSneakTransferStatement {
	rStar, _ := rand.Int(rand.Reader, ORDER)
	return &ZKSneakTransferStatement{rStar: rStar}
}

func (statement *ZKSneakTransferStatement) AddRelation(C *ElGamalEnc, pk *bn256.G1Affine, b *big.Int, bDelta *big.Int, sk *big.Int) error {
	// valid pk or not
	if sk != nil {
		oriPk := bn128.G1ScalarBaseMult(sk)
		if !oriPk.Equal(pk) {
			return errors.New("invalid pk")
		}
	}
	// b' = b - b^{\Delta}
	var bPrime *big.Int
	var CTilde *ElGamalEnc
	if b != nil {
		bPrime = ffmath.Add(b, bDelta)
		// refresh bPrime Enc
		CTilde = twistedElgamal_bn128.Enc(bPrime, statement.rStar, pk)
	}
	if bDelta.Cmp(big.NewInt(0)) < 0 && b == nil {
		return errors.New("you cannot transfer funds to accounts that do not belong to you")
	}
	// r \gets_R Z_p
	r, _ := rand.Int(rand.Reader, ORDER)
	// C^{\Delta} = (pk^r,g^r h^{b^{\Delta}})
	CDelta := twistedElgamal_bn128.Enc(bDelta, r, pk)
	// C' = C * C^{\Delta}
	CPrime := twistedElgamal_bn128.EncAdd(C, CDelta)
	relation := &ZKSneakTransferRelation{
		Public: &ZKSneakTransferPublic{CPrime: CPrime,
			CTilde: CTilde,
			CDelta: CDelta,
			Pk:     pk,},
		Witness: &ZKSneakTransferWitness{bDelta: bDelta,
			bPrime: bPrime,
			sk:     sk,
			r:      r,},
	}
	statement.Relations = append(statement.Relations, relation)
	return nil
}

type ZKSneakTransferRelation struct {
	Public  *ZKSneakTransferPublic
	Witness *ZKSneakTransferWitness
}

type ZKSneakTransferPublic struct {
	// public
	CPrime *ElGamalEnc
	// public
	CTilde *ElGamalEnc
	// public
	CDelta *ElGamalEnc
	// public
	Pk *bn256.G1Affine
}

type ZKSneakTransferWitness struct {
	// secret
	bDelta *big.Int
	// secret
	bPrime *big.Int
	// secret
	sk *big.Int
	// secret
	r *big.Int
}
