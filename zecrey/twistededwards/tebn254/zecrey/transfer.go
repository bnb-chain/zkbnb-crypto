package zecrey

import (
	"bytes"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

func ProvePTransfer(relation *PTransferProofRelation) (proof *PTransferProof, err error) {
	if relation == nil || relation.Statements == nil {
		return nil, ErrInvalidParams
	}
	var (
		buf             bytes.Buffer
		A_sum           *Point
		secrets, gammas []*big.Int
		Vs              []*Point
	)
	// initialize proof
	proof = new(PTransferProof)
	// add Pts,G,H from relation
	proof.Pts = relation.Pts
	proof.G = relation.G
	proof.H = relation.H
	proof.Ht = relation.Ht
	// write public statements into buf
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	// commit phase
	n := len(relation.Statements)
	commitEntities := make([]*transferCommitValues, n)
	A_sum = curve.ZeroPoint()
	// for range proofs
	//secrets := make([]*big.Int, n) // accounts balance
	//gammas := make([]*big.Int, n)  // random values
	//Vs := make([]*Point, n)        // commitments for accounts balance
	for i, statement := range relation.Statements {
		// write common inputs into buf
		buf.Write(statement.C.CL.Marshal())
		buf.Write(statement.C.CR.Marshal())
		buf.Write(statement.CDelta.CL.Marshal())
		buf.Write(statement.CDelta.CR.Marshal())
		buf.Write(statement.T.Marshal())
		buf.Write(statement.Y.Marshal())
		buf.Write(statement.Pk.Marshal())
		buf.Write(statement.TCRprimeInv.Marshal())
		buf.Write(statement.CLprimeInv.Marshal())

		var (
			// statement values
			C, CDelta *ElGamalEnc
			pk        *Point
			sk        *big.Int
		)

		// statement values
		C = statement.C
		CDelta = statement.CDelta
		pk = statement.Pk
		sk = statement.Sk
		// initialize commit values
		commitEntities[i] = new(transferCommitValues)
		// start Sigma protocol
		// commit enc values
		commitEntities[i].alpha_r, commitEntities[i].alpha_bDelta, commitEntities[i].A_CLDelta, commitEntities[i].A_CRDelta = commitValidEnc(pk, G, H)
		// prove \sum_{i=1}^n b_i^{\Delta}
		A_sum = curve.Add(A_sum, curve.ScalarMul(G, commitEntities[i].alpha_bDelta))
		// write into buf
		buf.Write(commitEntities[i].A_CLDelta.Marshal())
		buf.Write(commitEntities[i].A_CRDelta.Marshal())
		// if user does not own the account, then commit bDelta.
		if sk == nil {
			commitEntities[i].alpha_rstarSubr, commitEntities[i].A_YDivCRDelta = commitValidDelta(G)
		} else { // Otherwise, commit ownership
			// commit to ownership
			commitEntities[i].alpha_rstarSubrbar, commitEntities[i].alpha_rbar, commitEntities[i].alpha_bprime,
				commitEntities[i].alpha_sk, commitEntities[i].alpha_skInv,
				commitEntities[i].A_YDivT, commitEntities[i].A_T,
				commitEntities[i].A_pk, commitEntities[i].A_TDivCPrime = commitOwnership(G, H, curve.Neg(curve.Add(C.CL, CDelta.CL))) // commit to tokenId
		}
		// generate sub proofs
		commitValues := commitEntities[i]
		proof.SubProofs = append(proof.SubProofs, &PTransferSubProof{
			A_CLDelta:     commitValues.A_CLDelta,
			A_CRDelta:     commitValues.A_CRDelta,
			A_YDivCRDelta: commitValues.A_YDivCRDelta,
			A_YDivT:       commitValues.A_YDivT,
			A_T:           commitValues.A_T,
			A_pk:          commitValues.A_pk,
			A_TDivCPrime:  commitValues.A_TDivCPrime,
			// original balance enc
			C: statement.C,
			// delta balance enc
			CDelta: statement.CDelta,
			// new pedersen commitment for new balance
			T: statement.T,
			// new pedersen commitment for deleta balance or new balance
			Y: statement.Y,
			// public key
			Pk: statement.Pk,
			// T (C_R + C_R^{\Delta})^{-1}
			TCRprimeInv: statement.TCRprimeInv,
			// (C_L + C_L^{\Delta})^{-1}
			CLprimeInv: statement.CLprimeInv,
		})
		// complete range proof statements
		secrets = append(secrets, statement.BStar)
		gammas = append(gammas, statement.RStar)
		Vs = append(Vs, statement.Y)
	}
	// set A_sum
	proof.A_sum = A_sum
	// make sure the length of commitEntities and statements is equal
	if len(commitEntities) != len(relation.Statements) {
		return nil, ErrStatements
	}
	// challenge phase
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// random challenge for sim
	c1 := curve.RandomValue()
	c2 := ffmath.Xor(c, c1)
	proof.C1 = c1
	proof.C2 = c2
	for i := 0; i < len(commitEntities); i++ {
		// get values first
		commitValues := commitEntities[i]
		statement := relation.Statements[i]
		z_r, z_bDelta := respondValidEnc(
			statement.R, statement.BDelta, commitValues.alpha_r, commitValues.alpha_bDelta, c,
		)
		// if the user does not own the account, run simOwnership
		if statement.Sk == nil && commitValues.alpha_rstarSubr != nil {
			z_rstarSubr := respondValidDelta(
				ffmath.SubMod(statement.RStar, statement.R, Order),
				commitValues.alpha_rstarSubr, c1,
			)
			A_YDivT, A_T, A_pk, A_TDivCPrime,
			z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv := simOwnership(
				G, H, statement.Y, statement.T, statement.Pk,
				statement.TCRprimeInv, statement.CLprimeInv,
				c2,
			)
			// complete sub proofs
			proof.SubProofs[i].Z_rstarSubr = z_rstarSubr
			proof.SubProofs[i].A_YDivT = A_YDivT
			proof.SubProofs[i].A_T = A_T
			proof.SubProofs[i].A_pk = A_pk
			proof.SubProofs[i].A_TDivCPrime = A_TDivCPrime
			proof.SubProofs[i].Z_rstarSubrbar = z_rstarSubrbar
			proof.SubProofs[i].Z_rbar = z_rbar
			proof.SubProofs[i].Z_bprime = z_bprime
			proof.SubProofs[i].Z_sk = z_sk
			proof.SubProofs[i].Z_skInv = z_skInv
		} else { // otherwise, run simValidDelta
			A_YDivCRDelta, z_rstarSubr := simValidDelta(
				statement.CDelta.CR, statement.Y, G,
				c1,
			)
			z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv := respondOwnership(
				ffmath.SubMod(statement.RStar, statement.RBar, Order),
				statement.RBar, statement.BPrime, statement.Sk,
				commitValues.alpha_rstarSubrbar, commitValues.alpha_rbar,
				commitValues.alpha_bprime, commitValues.alpha_sk, commitValues.alpha_skInv, c2,
			)
			// complete sub proofs
			proof.SubProofs[i].A_YDivCRDelta = A_YDivCRDelta
			proof.SubProofs[i].Z_rstarSubr = z_rstarSubr
			proof.SubProofs[i].Z_rstarSubrbar = z_rstarSubrbar
			proof.SubProofs[i].Z_rbar = z_rbar
			proof.SubProofs[i].Z_bprime = z_bprime
			proof.SubProofs[i].Z_sk = z_sk
			proof.SubProofs[i].Z_skInv = z_skInv
			// commit to Pt = Ht^{sk}
			A_Pt, z_tsk := provePt(nil, statement.Sk, relation.Ht, c)
			proof.A_Pts = append(proof.A_Pts, A_Pt)
			proof.Z_tsks = append(proof.Z_tsks, z_tsk)
		}
		// compute the range proof
		rangeProof, err := commitRange.Prove(statement.BStar, statement.RStar, H, G, N)
		if err != nil {
			return nil, err
		}
		// set the range proof into sub proofs
		proof.SubProofs[i].CRangeProof = rangeProof
		// complete sub proofs
		proof.SubProofs[i].Z_r = z_r
		proof.SubProofs[i].Z_bDelta = z_bDelta
	}
	slen := len(secrets)
	glen := len(gammas)
	Vlen := len(Vs)
	if slen != glen || slen != Vlen {
		return nil, ErrInvalidBPParams
	}
	// response phase
	return proof, nil
}

func (proof *PTransferProof) Verify() (bool, error) {
	// generate the challenge
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	for _, subProof := range proof.SubProofs {
		// write common inputs into buf
		buf.Write(subProof.C.CL.Marshal())
		buf.Write(subProof.C.CR.Marshal())
		buf.Write(subProof.CDelta.CL.Marshal())
		buf.Write(subProof.CDelta.CR.Marshal())
		buf.Write(subProof.T.Marshal())
		buf.Write(subProof.Y.Marshal())
		buf.Write(subProof.Pk.Marshal())
		buf.Write(subProof.TCRprimeInv.Marshal())
		buf.Write(subProof.CLprimeInv.Marshal())
		buf.Write(subProof.A_CLDelta.Marshal())
		buf.Write(subProof.A_CRDelta.Marshal())
	}
	// c = hash()
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// verify c
	cCheck := ffmath.Xor(proof.C1, proof.C2)
	if !ffmath.Equal(c, cCheck) {
		return false, ErrInvalidChallenge
	}
	// verify Pt proof
	if len(proof.Pts) != len(proof.A_Pts) || len(proof.Pts) != len(proof.Z_tsks) {
		return false, ErrInvalidParams
	}
	for i := 0; i < len(proof.Pts); i++ {
		l := curve.ScalarMul(proof.Ht, proof.Z_tsks[i])
		r := curve.Add(proof.A_Pts[i], curve.ScalarMul(proof.Pts[i], c))
		if !l.Equal(r) {
			return false, nil
		}
	}
	g := proof.G
	h := proof.H
	// verify sub proofs
	lSum := curve.ZeroPoint()
	for _, subProof := range proof.SubProofs {
		// verify range proof
		rangeRes, err := subProof.CRangeProof.Verify()
		if err != nil || !rangeRes {
			return false, err
		}
		// verify valid enc
		validEncRes, err := verifyValidEnc(
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, g, h, subProof.CDelta.CR, subProof.A_CRDelta,
			c,
			subProof.Z_r, subProof.Z_bDelta,
		)
		if err != nil || !validEncRes {
			return false, err
		}
		YDivCRDelta := curve.Add(subProof.Y, curve.Neg(subProof.CDelta.CR))
		// verify valid Delta
		validDeltaRes, err := verifyValidDelta(
			g, YDivCRDelta, subProof.A_YDivCRDelta,
			proof.C1,
			subProof.Z_rstarSubr,
		)
		if err != nil || !validDeltaRes {
			return false, err
		}
		YDivT := curve.Add(subProof.Y, curve.Neg(subProof.T))
		// verify ownership
		ownershipRes, err := verifyOwnership(
			g, YDivT, subProof.A_YDivT, h, subProof.T, subProof.A_T, subProof.Pk, subProof.A_pk,
			subProof.CLprimeInv, subProof.TCRprimeInv, subProof.A_TDivCPrime,
			proof.C2,
			subProof.Z_rstarSubrbar, subProof.Z_rbar,
			subProof.Z_bprime, subProof.Z_sk, subProof.Z_skInv,
		)
		if err != nil || !ownershipRes {
			return false, err
		}
		// set z_bDeltas for sum proof
		lSum = curve.Add(lSum, curve.ScalarMul(g, subProof.Z_bDelta))
	}

	// verify sum proof
	rSum := proof.A_sum
	return lSum.Equal(rSum), nil
}

/**
commit phase for R_{ValidDelta} = {Y/C_R^{\Delta} = g^{r^{\star} - r}}
@g: generator
*/
func commitValidDelta(g *Point) (alpha_rstarSubr *big.Int, A_YDivCRDelta *Point) {
	alpha_rstarSubr = curve.RandomValue()
	A_YDivCRDelta = curve.ScalarMul(g, alpha_rstarSubr)
	return
}

func respondValidDelta(rstarSubr, alpha_rstarSubr, c *big.Int) (z_rstarSubr *big.Int) {
	z_rstarSubr = ffmath.AddMod(alpha_rstarSubr, ffmath.Multiply(c, rstarSubr), Order)
	return
}

func verifyValidDelta(
	g, YDivCRDelta, A_YDivCRDelta *Point,
	c *big.Int,
	z_rstarSubr *big.Int,
) (bool, error) {
	if g == nil || YDivCRDelta == nil || A_YDivCRDelta == nil || c == nil || z_rstarSubr == nil {
		return false, ErrInvalidParams
	}
	l := curve.ScalarMul(g, z_rstarSubr)
	r := curve.Add(A_YDivCRDelta, curve.ScalarMul(YDivCRDelta, c))
	return l.Equal(r), nil
}

func simValidDelta(
	C_RDelta, Y, g *Point, cSim *big.Int,
) (
	A_YDivCRDelta *Point, z_rstarSubr *big.Int,
) {
	z_rstarSubr = curve.RandomValue()
	A_YDivCRDelta = curve.Add(
		curve.ScalarMul(g, z_rstarSubr),
		curve.ScalarMul(curve.Neg(curve.Add(Y, curve.Neg(C_RDelta))), cSim),
	)
	return
}

/**
commit phase for R_{Ownership} = {
Y/T = g^{r^{\star} - \bar{r}} \wedge
T = g^{\bar{r}} h^{b'} \wedge
pk = g^{sk} \wedge
T(C_R + C_R^{\Delta})^{-1} = [(C_L + C_L^{\Delta})^{-1}]^{sk^{-1}} g^{\bar{r}} \wedge}
@g: generator
@h: generator
@hDec: (C_L + C_L^{\Delta})^{-1}
*/
func commitOwnership(g, h, hDec *Point) (
	alpha_rstarSubrbar, alpha_rbar, alpha_bprime, alpha_sk, alpha_skInv *big.Int,
	A_YDivT, A_T, A_pk, A_TDivCPrime *Point,
) {
	alpha_rstarSubrbar = curve.RandomValue()
	alpha_rbar = curve.RandomValue()
	alpha_bprime = curve.RandomValue()
	alpha_sk = curve.RandomValue()
	alpha_skInv = ffmath.ModInverse(alpha_sk, Order)
	A_YDivT = curve.ScalarMul(g, alpha_rstarSubrbar)
	A_T = curve.Add(curve.ScalarMul(g, alpha_rbar), curve.ScalarMul(h, alpha_bprime))
	A_pk = curve.ScalarMul(g, alpha_sk)
	A_TDivCPrime = curve.Add(curve.ScalarMul(hDec, alpha_skInv), curve.ScalarMul(g, alpha_rbar))
	return
}

func respondOwnership(
	rstarSubrbar, rbar, bprime, sk,
	alpha_rstarSubrbar, alpha_rbar, alpha_bprime, alpha_sk, alpha_skInv, c *big.Int,
) (
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv *big.Int,
) {
	z_rstarSubrbar = ffmath.AddMod(alpha_rstarSubrbar, ffmath.Multiply(c, rstarSubrbar), Order)
	z_rbar = ffmath.AddMod(alpha_rbar, ffmath.Multiply(c, rbar), Order)
	z_bprime = ffmath.AddMod(alpha_bprime, ffmath.Multiply(c, bprime), Order)
	skInv := ffmath.ModInverse(sk, Order)
	z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, skInv), Order)
	return
}

func verifyOwnership(
	g, YDivT, A_YDivT, h, T, A_T, pk, A_pk, CLprimeInv, TCRprimeInv, A_TCRprimeInv *Point,
	c *big.Int,
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv *big.Int,
) (bool, error) {
	// verify Y/T = g^{r^{\star} - \bar{r}}
	l1 := curve.ScalarMul(g, z_rstarSubrbar)
	r1 := curve.Add(A_YDivT, curve.ScalarMul(YDivT, c))
	if !l1.Equal(r1) {
		return false, nil
	}
	// verify T = g^{\bar{r}} h^{b'}
	gzrbar := curve.ScalarMul(g, z_rbar)
	l2 := curve.Add(gzrbar, curve.ScalarMul(h, z_bprime))
	r2 := curve.Add(A_T, curve.ScalarMul(T, c))
	if !l2.Equal(r2) {
		return false, nil
	}
	// verify pk = g^{sk}
	l3 := curve.ScalarMul(g, z_sk)
	r3 := curve.Add(A_pk, curve.ScalarMul(pk, c))
	if !l3.Equal(r3) {
		return false, nil
	}
	// verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
	l4 := curve.Add(gzrbar, curve.ScalarMul(CLprimeInv, z_skInv))
	r4 := curve.Add(A_TCRprimeInv, curve.ScalarMul(TCRprimeInv, c))
	return l4.Equal(r4), nil
}

func simOwnership(
	g, h, Y, T, pk, TCRprimeInv, CLprimeInv *Point,
	cSim *big.Int,
) (
	A_YDivT, A_T, A_pk, A_TDivCPrime *Point,
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv *big.Int,
) {
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv =
		curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue()
	// A_{Y/T} = g^{z_{r^{\star} - \bar{r}}} (Y T^{-1})^{-c}
	A_YDivT = curve.Add(
		curve.ScalarMul(g, z_rstarSubrbar),
		curve.ScalarMul(curve.Neg(curve.Add(Y, curve.Neg(T))), cSim),
	)
	// A_T = g^{z_{\bar{r}}} h^{z_{b'}} (T)^{-c}
	A_T = curve.Add(
		curve.Add(curve.ScalarMul(g, z_rbar), curve.ScalarMul(h, z_bprime)),
		curve.ScalarMul(curve.Neg(T), cSim),
	)
	// A_{pk} = g^{z_{sk}} pk^{-c}
	A_pk = curve.Add(
		curve.ScalarMul(g, z_sk),
		curve.ScalarMul(curve.Neg(pk), cSim),
	)
	// A_{T(C_R + C_R^{\Delta})^{-1}} =
	// g^{z_{\bar{r}}} [(C_L + C_L^{\Delta})^{-1}]^{z_{skInv}} [T(C_R + C_R^{\Delta})^{-1}]^{-c}
	A_TDivCPrime = curve.Add(
		curve.Add(curve.ScalarMul(g, z_rbar), curve.ScalarMul(CLprimeInv, z_skInv)),
		curve.ScalarMul(curve.Neg(TCRprimeInv), cSim),
	)
	return
}
