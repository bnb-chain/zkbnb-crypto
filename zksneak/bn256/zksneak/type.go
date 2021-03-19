package zksneak

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/elgamal/bn256/twistedElgamal"
	"ZKSneak-crypto/math"
	"ZKSneak-crypto/rangeProofs/bn256/bulletProofs"
	"crypto/rand"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type (
	ElGamalEnc = twistedElgamal.ElGamalEnc
	BulletProofSetupParams = bulletProofs.BulletProofSetupParams
	BulletProof = bulletProofs.BulletProof
)

type ZKSneakTransferProof struct {
	EncProofs   []*AnonEncProof
	RangeProofs []*AnonRangeProof
	EqualProof  *AnonEqualProof
}

type AnonEncProof struct {
	Z *big.Int
	A *bn256.G1Affine
	R *bn256.G1Affine
	G *bn256.G1Affine
}

type AnonRangeProof struct {
	RangeProof *BulletProof
	SkProof    *ChaumPedersenProof
}

type ChaumPedersenProof struct {
	Z      *big.Int
	G, U   *bn256.G1Affine
	Vt, Wt *bn256.G1Affine
	V, W   *bn256.G1Affine
}

type AnonEqualProof struct {
	ZArr  []*big.Int
	UtArr []*bn256.G1Affine
	GArr  []*bn256.G1Affine
	UArr  []*bn256.G1Affine
}

type ZKSneakTransferStatement struct {
	Relations []*ZKSneakTransferRelation
	RStar     *big.Int
}

func NewStatement() *ZKSneakTransferStatement {
	rStar, _ := rand.Int(rand.Reader, ORDER)
	return &ZKSneakTransferStatement{RStar: rStar}
}

func (statement *ZKSneakTransferStatement) AddRelation(C *ElGamalEnc, pk *bn256.G1Affine, b *big.Int, bDelta *big.Int, sk *big.Int) error {
	// valid pk or not
	if sk != nil {
		oriPk := zbn256.G1ScalarBaseMult(sk)
		if !oriPk.Equal(pk) {
			return errors.New("invalid pk")
		}
	}
	// b' = b - b^{\Delta}
	var bPrime *big.Int
	var CTilde *ElGamalEnc
	if b != nil {
		bPrime = math.Add(b, bDelta)
		// refresh bPrime Enc
		CTilde = twistedElgamal.Enc(bPrime, statement.RStar, pk)
	}
	if bDelta.Cmp(big.NewInt(0)) < 0 && b == nil {
		return errors.New("you cannot transfer funds to accounts that do not belong to you")
	}
	// r \gets_R Z_p
	r, _ := rand.Int(rand.Reader, ORDER)
	// C^{\Delta} = (pk^r,G^r h^{b^{\Delta}})
	CDelta := twistedElgamal.Enc(bDelta, r, pk)
	// C' = C * C^{\Delta}
	CPrime := twistedElgamal.EncAdd(C, CDelta)
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
