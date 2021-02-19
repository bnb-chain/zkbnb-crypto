package zksneak_bn128

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/sigmaProtocol/chaum-pedersen_bn128"
	"ZKSneak/ZKSneak-crypto/sigmaProtocol/linear_bn128"
	"ZKSneak/ZKSneak-crypto/sigmaProtocol/schnorr_bn128"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove CL
func (proof *ZKSneakProof) ProveAnonEnc(relations []*ZKSneakRelation) {
	for _, relation := range relations {
		zi, Ai := schnorr_bn128.Prove(relation.r, relation.Pk, relation.CDelta.CL)
		proof.EncProofs = append(proof.EncProofs, &AnonEncProof{z: zi, A: Ai, R: relation.CDelta.CL, g: relation.Pk})
	}
}

func (proof *ZKSneakProof) VerifyAnonEnc() bool {
	for _, encProof := range proof.EncProofs {
		res := schnorr_bn128.Verify(encProof.z, encProof.A, encProof.R, encProof.g)
		if !res {
			return false
		}
	}
	return true
}

// prove bDelta range or (sk and bPrime range)
func (proof *ZKSneakProof) ProveAnonRange(statement *ZKSneakStatement, params *BulletProofSetupParams) error {
	relations := statement.Relations
	for _, relation := range relations {
		// TODO OR proof
		// bDelta range proof
		if relation.BDelta.Cmp(big.NewInt(0)) < 0 {
			// u = C'_{i,r} / \tilde{C}_{i,r}
			u := bn128.G1AffineMul(relation.CPrime.CR, new(bn256.G1Affine).Neg(relation.CTilde.CR))
			w := bn128.G1AffineMul(relation.CTilde.CL, new(bn256.G1Affine).Neg(relation.CPrime.CL))
			g := bn128.GetG1BaseAffine()
			v := relation.Pk
			z, Vt, Wt := chaum_pedersen_bn128.Prove(relation.Sk, g, u, v, w)
			bulletProof, err := bp_bn128.Prove(relation.BPrime, statement.RStar, relation.CTilde.CR, *params)
			if err != nil {
				return err
			}
			proof.RangeProofs = append(proof.RangeProofs, &AnonRangeProof{RangeProof: &bulletProof, SkProof: &ChaumPedersenProof{z: z, g: g, u: u, Vt: Vt, Wt: Wt, v: relation.Pk, w: w}})
		} else {
			bulletProof, err := bp_bn128.Prove(relation.BDelta, relation.r, relation.CDelta.CR, *params)
			if err != nil {
				return err
			}
			proof.RangeProofs = append(proof.RangeProofs, &AnonRangeProof{RangeProof: &bulletProof})
		}
	}
	return nil
}

func (proof *ZKSneakProof) VerifyAnonRange() bool {
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

func (proof *ZKSneakProof) ProveEqual(relations []*ZKSneakRelation) {
	var xArr []*big.Int
	for _, relation := range relations {
		xArr = append(xArr, relation.BDelta)
	}
	n := len(xArr)
	var gArr []*bn256.G1Affine
	g := bn128.GetG1BaseAffine()
	for i := 0; i < n; i++ {
		gArr = append(gArr, g)
	}
	uArr := []*bn256.G1Affine{bn128.GetG1InfinityPoint()}
	zArr, UtArr := linear_bn128.Prove(xArr, gArr, uArr)
	proof.EqualProof = &AnonEqualProof{ZArr: zArr, gArr: gArr, UtArr: UtArr, uArr: uArr}
}

func (proof *ZKSneakProof) VerifyEqual() bool {
	linearProof := proof.EqualProof
	linearVerifyRes := linear_bn128.Verify(linearProof.ZArr, linearProof.gArr, linearProof.uArr, linearProof.UtArr)
	if !linearVerifyRes {
		return false
	}
	return true
}
