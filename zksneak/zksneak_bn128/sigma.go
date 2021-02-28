package zksneak_bn128

import (
	"ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/sigmaProtocol/chaum-pedersen_bn128"
	"ZKSneak-crypto/sigmaProtocol/linear_bn128"
	"ZKSneak-crypto/sigmaProtocol/schnorr_bn128"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove CL
func (proof *ZKSneakTransferProof) ProveAnonEnc(relations []*ZKSneakTransferRelation) {
	for _, relation := range relations {
		zi, Ai := schnorr_bn128.Prove(relation.Witness.r, relation.Public.Pk, relation.Public.CDelta.CL)
		proof.EncProofs = append(proof.EncProofs, &AnonEncProof{z: zi, A: Ai, R: relation.Public.CDelta.CL, g: relation.Public.Pk})
	}
}

func (proof *ZKSneakTransferProof) VerifyAnonEnc() bool {
	for _, encProof := range proof.EncProofs {
		res := schnorr_bn128.Verify(encProof.z, encProof.A, encProof.R, encProof.g)
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
			// u = C'_{i,r} / \tilde{C}_{i,r}
			u := bn128.G1AffineMul(relation.Public.CPrime.CR, new(bn256.G1Affine).Neg(relation.Public.CTilde.CR))
			w := new(bn256.G1Affine).ScalarMultiplication(u, relation.Witness.sk)
			g := bn128.GetG1BaseAffine()
			v := relation.Public.Pk
			z, Vt, Wt := chaum_pedersen_bn128.Prove(relation.Witness.sk, g, u, v, w)
			bulletProof, err := bp_bn128.Prove(relation.Witness.bPrime, statement.rStar, relation.Public.CTilde.CR, *params)
			if err != nil {
				return err
			}
			proof.RangeProofs = append(proof.RangeProofs, &AnonRangeProof{RangeProof: &bulletProof, SkProof: &ChaumPedersenProof{z: z, g: g, u: u, Vt: Vt, Wt: Wt, v: relation.Public.Pk, w: w}})
		} else {
			bulletProof, err := bp_bn128.Prove(relation.Witness.bDelta, relation.Witness.r, relation.Public.CDelta.CR, *params)
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
			pedersenVerifyRes := chaum_pedersen_bn128.Verify(pedersenProof.z, pedersenProof.g, pedersenProof.u, pedersenProof.Vt, pedersenProof.Wt, pedersenProof.v, pedersenProof.w)
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
	g := bn128.GetG1BaseAffine()
	for i := 0; i < n; i++ {
		gArr = append(gArr, g)
	}
	uArr := []*bn256.G1Affine{bn128.GetG1InfinityPoint()}
	zArr, UtArr := linear_bn128.Prove(xArr, gArr, uArr)
	proof.EqualProof = &AnonEqualProof{zArr: zArr, gArr: gArr, UtArr: UtArr, uArr: uArr}
}

func (proof *ZKSneakTransferProof) VerifyEqual() bool {
	linearProof := proof.EqualProof
	linearVerifyRes := linear_bn128.Verify(linearProof.zArr, linearProof.gArr, linearProof.uArr, linearProof.UtArr)
	if !linearVerifyRes {
		return false
	}
	return true
}
