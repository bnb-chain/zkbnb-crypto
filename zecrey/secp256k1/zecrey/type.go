package zecrey

import (
	"Zecrey-crypto/ecc/zp256"
	"Zecrey-crypto/elgamal/secp256k1/twistedElgamal"
	"Zecrey-crypto/ffmath"
	"Zecrey-crypto/rangeProofs/secp256k1/bulletProofs"
	"crypto/rand"
	"errors"
	"math/big"
)

type (
	ElGamalEnc = twistedElgamal.ElGamalEnc
	BulletProofSetupParams = bulletProofs.BulletProofSetupParams
	BulletProof = bulletProofs.BulletProof
	P256 = zp256.P256
)

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

type ZKSneakTransferStatement struct {
	Relations []*ZKSneakTransferRelation
	RStar     *big.Int
}

func NewStatement() *ZKSneakTransferStatement {
	rStar, _ := rand.Int(rand.Reader, Order)
	return &ZKSneakTransferStatement{RStar: rStar}
}

func (statement *ZKSneakTransferStatement) AddRelation(C *ElGamalEnc, pk *P256, b *big.Int, bDelta *big.Int, sk *big.Int) error {
	// valid pk or not
	if sk != nil {
		oriPk := zp256.ScalarBaseMult(sk)
		if !zp256.Equal(oriPk, pk) {
			return errors.New("invalid pk")
		}
	}
	// b' = b - b^{\Delta}
	var bPrime *big.Int
	var CTilde *ElGamalEnc
	if b != nil {
		bPrime = ffmath.Add(b, bDelta)
		// refresh bPrime Enc
		CTilde = twistedElgamal.Enc(bPrime, statement.RStar, pk)
	}
	if bDelta.Cmp(big.NewInt(0)) < 0 && b == nil {
		return errors.New("you cannot transfer funds to accounts that do not belong to you")
	}
	// r \gets_R Z_p
	r, _ := rand.Int(rand.Reader, Order)
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
	Pk *P256
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
