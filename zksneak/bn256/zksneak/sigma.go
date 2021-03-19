package zksneak

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/rangeProofs/bn256/bulletProofs"
	"ZKSneak-crypto/sigmaProtocol/bn256/chaum-pedersen"
	"ZKSneak-crypto/sigmaProtocol/bn256/linear"
	"ZKSneak-crypto/sigmaProtocol/bn256/schnorr"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove CL = pk^r
func (proof *ZKSneakTransferProof) ProveAnonEnc(relations []*ZKSneakTransferRelation) {
	for _, relation := range relations {
		zi, Ai := schnorr.Prove(relation.Witness.r, relation.Public.Pk, relation.Public.CDelta.CL)
		proof.EncProofs = append(proof.EncProofs, &AnonEncProof{Z: zi, A: Ai, R: relation.Public.CDelta.CL, G: relation.Public.Pk})
	}
}

func (proof *ZKSneakTransferProof) VerifyAnonEnc() bool {
	for _, encProof := range proof.EncProofs {
		res := schnorr.Verify(encProof.Z, encProof.A, encProof.R, encProof.G)
		if !res {
			return false
		}
	}
	return true
}

// prove bDelta range or (sk and bPrime range)
func (proof *ZKSneakTransferProof) ProveAnonRange(statement *ZKSneakTransferStatement, params *BulletProofSetupParams) error {
	relations := statement.Relations
	for _, relation := range relations {
		// TODO OR proof
		// bDelta range proof
		if relation.Witness.bDelta.Cmp(big.NewInt(0)) < 0 {
			if relation.Witness.sk == nil || relation.Witness.bPrime == nil {
				return errors.New("you cannot transfer funds to accounts that do not belong to you")
			}
			// U = C'_{i,r} / \tilde{C}_{i,r}
			u := zbn256.G1AffineMul(relation.Public.CPrime.CR, new(bn256.G1Affine).Neg(relation.Public.CTilde.CR))
			w := new(bn256.G1Affine).ScalarMultiplication(u, relation.Witness.sk)
			g := zbn256.GetG1BaseAffine()
			v := relation.Public.Pk
			z, Vt, Wt := chaum_pedersen.Prove(relation.Witness.sk, g, u, v, w)
			bulletProof, err := bulletProofs.Prove(relation.Witness.bPrime, statement.RStar, relation.Public.CTilde.CR, *params)
			if err != nil {
				return err
			}
			proof.RangeProofs = append(proof.RangeProofs, &AnonRangeProof{RangeProof: &bulletProof, SkProof: &ChaumPedersenProof{Z: z, G: g, U: u, Vt: Vt, Wt: Wt, V: relation.Public.Pk, W: w}})
		} else {
			bulletProof, err := bulletProofs.Prove(relation.Witness.bDelta, relation.Witness.r, relation.Public.CDelta.CR, *params)
			if err != nil {
				return err
			}
			proof.RangeProofs = append(proof.RangeProofs, &AnonRangeProof{RangeProof: &bulletProof})
		}
	}
	return nil
}

func (proof *ZKSneakTransferProof) VerifyAnonRange() bool {
	for _, rangeProof := range proof.RangeProofs {
		if rangeProof.SkProof == nil {
			res, err := rangeProof.RangeProof.Verify()
			if err != nil || !res {
				return false
			}
		} else {
			rangeVerifyRes, err := rangeProof.RangeProof.Verify()
			if err != nil || !rangeVerifyRes {
				return false
			}
			pedersenProof := rangeProof.SkProof
			pedersenVerifyRes := chaum_pedersen.Verify(pedersenProof.Z, pedersenProof.G, pedersenProof.U, pedersenProof.Vt, pedersenProof.Wt, pedersenProof.V, pedersenProof.W)
			if !pedersenVerifyRes {
				return false
			}
		}
	}
	return true
}

func (proof *ZKSneakTransferProof) ProveEqual(relations []*ZKSneakTransferRelation) {
	var xArr []*big.Int
	for _, relation := range relations {
		xArr = append(xArr, relation.Witness.bDelta)
	}
	n := len(xArr)
	var gArr []*bn256.G1Affine
	g := zbn256.GetG1BaseAffine()
	for i := 0; i < n; i++ {
		gArr = append(gArr, g)
	}
	uArr := []*bn256.G1Affine{zbn256.GetG1InfinityPoint()}
	zArr, UtArr := linear.Prove(xArr, gArr, uArr)
	proof.EqualProof = &AnonEqualProof{ZArr: zArr, GArr: gArr, UtArr: UtArr, UArr: uArr}
}

func (proof *ZKSneakTransferProof) VerifyEqual() bool {
	linearProof := proof.EqualProof
	linearVerifyRes := linear.Verify(linearProof.ZArr, linearProof.GArr, linearProof.UArr, linearProof.UtArr)
	if !linearVerifyRes {
		return false
	}
	return true
}
