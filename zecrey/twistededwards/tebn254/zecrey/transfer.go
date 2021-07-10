/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package zecrey

import (
	"bytes"
	"fmt"
	"math/big"
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

var ownershipChan = make(chan int, 1)
var simChan = make(chan int, TransferSubProofCount-1)
var rangeChan = make(chan int, TransferSubProofSize)

func ProvePTransfer(relation *PTransferProofRelation) (proof *PTransferProof, err error) {
	if relation == nil || relation.Statements == nil || len(relation.Statements) != TransferSubProofCount {
		return nil, ErrInvalidParams
	}
	// Verify \sum b_i^{\Delta} + fee = 0
	sum := big.NewInt(0)
	for _, statement := range relation.Statements {
		sum.Add(sum, statement.BDelta)
	}
	sum.Add(sum, relation.Fee)
	// statements must be correct
	if !ffmath.Equal(sum, big.NewInt(0)) {
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
	// add Pt,G,Waste from relation
	proof.Pt = relation.Pt
	proof.G = relation.G
	proof.H = relation.H
	proof.Ht = relation.Ht
	proof.Fee = relation.Fee
	// write public statements into buf
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	buf.Write(proof.Fee.Bytes())
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
			go commitOwnershipRoutine(G, H, curve.Neg(curve.Add(C.CL, CDelta.CL)), commitEntities, i)
		}
		// generate sub proofs
		commitValues := commitEntities[i]
		proof.SubProofs[i] = &PTransferSubProof{
			A_CLDelta:     commitValues.A_CLDelta,
			A_CRDelta:     commitValues.A_CRDelta,
			A_YDivCRDelta: commitValues.A_YDivCRDelta,
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
		}
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
			go simOwnershipRoutine(
				G, H, statement.Y, statement.T, statement.Pk,
				statement.TCRprimeInv, statement.CLprimeInv,
				c2,
				proof, i,
			)
			// complete sub proofs
			proof.SubProofs[i].Z_rstarSubr = z_rstarSubr
		} else { // otherwise, run simValidDelta
			j := <-ownershipChan
			if j != i {
				return nil, ErrInvalidParams
			}
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
			proof.SubProofs[i].A_YDivT = commitValues.A_YDivT
			proof.SubProofs[i].A_T = commitValues.A_T
			proof.SubProofs[i].A_pk = commitValues.A_pk
			proof.SubProofs[i].A_TDivCPrime = commitValues.A_TDivCPrime
			proof.SubProofs[i].A_YDivCRDelta = A_YDivCRDelta

			proof.SubProofs[i].A_YDivCRDelta = A_YDivCRDelta
			proof.SubProofs[i].Z_rstarSubr = z_rstarSubr
			proof.SubProofs[i].Z_rstarSubrbar = z_rstarSubrbar
			proof.SubProofs[i].Z_rbar = z_rbar
			proof.SubProofs[i].Z_bprime = z_bprime
			proof.SubProofs[i].Z_sk = z_sk
			proof.SubProofs[i].Z_skInv = z_skInv
			// commit to Pt = Ht^{sk}
			A_Pt, z_tsk := provePt(nil, statement.Sk, relation.Ht, c)
			proof.A_Pt = A_Pt
			proof.Z_tsk = z_tsk
		}
		// compute the range proof
		go ProveRangeRoutine(statement.BStar, statement.RStar, statement.Y, statement.Rs, H, G, proof, i)
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
	for i := 0; i < TransferSubProofCount-1; i++ {
		index := <-simChan
		if index == -1 {
			return nil, ErrUnableSimOwnership
		}
	}
	for i := 0; i < TransferSubProofCount; i++ {
		index := <-rangeChan
		if index == -1 {
			return nil, ErrUnableRangeProof
		}
	}
	// response phase
	return proof, nil
}

func ProveRangeRoutine(b *big.Int, r *big.Int, T *Point, rs [RangeMaxBits]*big.Int, g, h *Point, proof *PTransferProof, i int) {
	rangeProof, err := commitRange.Prove(b, r, T, rs, g, h)
	if err != nil {
		rangeChan <- -1
	}
	proof.SubProofs[i].CRangeProof = rangeProof
	rangeChan <- i
}

func (proof *PTransferProof) Verify() (bool, error) {
	// generate the challenge
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	buf.Write(proof.Fee.Bytes())
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
	// Verify c
	cCheck := ffmath.Xor(proof.C1, proof.C2)
	if !ffmath.Equal(c, cCheck) {
		return false, ErrInvalidChallenge
	}
	// Verify Pt proof
	l := curve.ScalarMul(proof.Ht, proof.Z_tsk)
	r := curve.Add(proof.A_Pt, curve.ScalarMul(proof.Pt, c))
	if !l.Equal(r) {
		return false, nil
	}
	g := proof.G
	h := proof.H
	// Verify sub proofs
	lSum := curve.ZeroPoint()
	for _, subProof := range proof.SubProofs {
		// Verify range proof
		rangeRes, err := subProof.CRangeProof.Verify()
		if err != nil || !rangeRes {
			return false, err
		}
		// Verify valid enc
		validEncRes, err := verifyValidEnc(
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, g, h, subProof.CDelta.CR, subProof.A_CRDelta,
			c,
			subProof.Z_r, subProof.Z_bDelta,
		)
		if err != nil || !validEncRes {
			return false, err
		}
		YDivCRDelta := curve.Add(subProof.Y, curve.Neg(subProof.CDelta.CR))
		// Verify valid Delta
		validDeltaRes, err := verifyValidDelta(
			g, YDivCRDelta, subProof.A_YDivCRDelta,
			proof.C1,
			subProof.Z_rstarSubr,
		)
		if err != nil || !validDeltaRes {
			return false, err
		}
		YDivT := curve.Add(subProof.Y, curve.Neg(subProof.T))
		// Verify ownership
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

	// Verify sum proof
	gNeg := curve.Neg(proof.G)
	feec := ffmath.MultiplyMod(proof.Fee, c, Order)
	rSum := curve.Add(proof.A_sum, curve.ScalarMul(gNeg, feec))
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

/*
	verifyValidDelta verifys the delta proof
	@g: the generator
	@YDivCRDelta: public inputs
	@A_YDivCRDelta: the random commitment
	@c: the challenge
	@z_rstarSubr: response values for valid delta proof
*/
func verifyValidDelta(
	g, YDivCRDelta, A_YDivCRDelta *Point,
	c *big.Int,
	z_rstarSubr *big.Int,
) (bool, error) {
	if g == nil || YDivCRDelta == nil || A_YDivCRDelta == nil || c == nil || z_rstarSubr == nil {
		return false, ErrInvalidParams
	}
	// g^{z_r^{\star}} == A_{Y/(C_R^{\Delta})} [Y/(C_R^{\Delta})]^c
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

func commitOwnershipRoutine(g, h, hDec *Point, commitEntities []*transferCommitValues, i int) {
	commitEntities[i].alpha_rstarSubrbar = curve.RandomValue()
	commitEntities[i].alpha_rbar = curve.RandomValue()
	commitEntities[i].alpha_bprime = curve.RandomValue()
	commitEntities[i].alpha_sk = curve.RandomValue()
	commitEntities[i].alpha_skInv = ffmath.ModInverse(commitEntities[i].alpha_sk, Order)
	commitEntities[i].A_YDivT = curve.ScalarMul(g, commitEntities[i].alpha_rstarSubrbar)
	commitEntities[i].A_T = curve.Add(curve.ScalarMul(g, commitEntities[i].alpha_rbar), curve.ScalarMul(h, commitEntities[i].alpha_bprime))
	commitEntities[i].A_pk = curve.ScalarMul(g, commitEntities[i].alpha_sk)
	commitEntities[i].A_TDivCPrime = curve.Add(curve.ScalarMul(hDec, commitEntities[i].alpha_skInv), curve.ScalarMul(g, commitEntities[i].alpha_rbar))
	ownershipChan <- i
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

/*
	verifyOwnership verifys the ownership of the account
	@YDivT,T,pk,CLprimeInv,TCRprimeInv: public inputs
	@A_YDivT,A_T,A_pk,A_TCRprimeInv: random commitments
	@g,h: generators
	@c: the challenge
	@z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv: response values for valid delta proof
*/
func verifyOwnership(
	g, YDivT, A_YDivT, h, T, A_T, pk, A_pk, CLprimeInv, TCRprimeInv, A_TCRprimeInv *Point,
	c *big.Int,
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv *big.Int,
) (bool, error) {
	// Verify Y/T = g^{r^{\star} - \bar{r}}
	l1 := curve.ScalarMul(g, z_rstarSubrbar)
	r1 := curve.Add(A_YDivT, curve.ScalarMul(YDivT, c))
	if !l1.Equal(r1) {
		return false, nil
	}
	// Verify T = g^{\bar{r}} h^{b'}
	gzrbar := curve.ScalarMul(g, z_rbar)
	l2 := curve.Add(gzrbar, curve.ScalarMul(h, z_bprime))
	r2 := curve.Add(A_T, curve.ScalarMul(T, c))
	if !l2.Equal(r2) {
		return false, nil
	}
	// Verify pk = g^{sk}
	l3 := curve.ScalarMul(g, z_sk)
	r3 := curve.Add(A_pk, curve.ScalarMul(pk, c))
	if !l3.Equal(r3) {
		return false, nil
	}
	// Verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
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

func simOwnershipRoutine(
	g, h, Y, T, pk, TCRprimeInv, CLprimeInv *Point,
	cSim *big.Int,
	proof *PTransferProof, i int,
) {
	proof.SubProofs[i].Z_rstarSubrbar, proof.SubProofs[i].Z_rbar, proof.SubProofs[i].Z_bprime, proof.SubProofs[i].Z_sk, proof.SubProofs[i].Z_skInv =
		curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue()
	// A_{Y/T} = g^{z_{r^{\star} - \bar{r}}} (Y T^{-1})^{-c}
	proof.SubProofs[i].A_YDivT = curve.Add(
		curve.ScalarMul(g, proof.SubProofs[i].Z_rstarSubrbar),
		curve.ScalarMul(curve.Neg(curve.Add(Y, curve.Neg(T))), cSim),
	)
	// A_T = g^{z_{\bar{r}}} h^{z_{b'}} (T)^{-c}
	proof.SubProofs[i].A_T = curve.Add(
		curve.Add(curve.ScalarMul(g, proof.SubProofs[i].Z_rbar), curve.ScalarMul(h, proof.SubProofs[i].Z_bprime)),
		curve.ScalarMul(curve.Neg(T), cSim),
	)
	// A_{pk} = g^{z_{sk}} pk^{-c}
	proof.SubProofs[i].A_pk = curve.Add(
		curve.ScalarMul(g, proof.SubProofs[i].Z_sk),
		curve.ScalarMul(curve.Neg(pk), cSim),
	)
	// A_{T(C_R + C_R^{\Delta})^{-1}} =
	// g^{z_{\bar{r}}} [(C_L + C_L^{\Delta})^{-1}]^{z_{skInv}} [T(C_R + C_R^{\Delta})^{-1}]^{-c}
	proof.SubProofs[i].A_TDivCPrime = curve.Add(
		curve.Add(curve.ScalarMul(g, proof.SubProofs[i].Z_rbar), curve.ScalarMul(CLprimeInv, proof.SubProofs[i].Z_skInv)),
		curve.ScalarMul(curve.Neg(TCRprimeInv), cSim),
	)
	simChan <- i
}

func TryOnceTransfer() PTransferProof {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	//_, pk4 := twistedElgamal.GenKeyPair()
	//b4 := big.NewInt(4)
	//r4 := curve.RandomValue()
	b1Enc, _ := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, _ := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, _ := twistedElgamal.Enc(b3, r3, pk3)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	relation, _ := NewPTransferProofRelation(1, big.NewInt(1))
	relation.AddStatement(b1Enc, pk1, b1, big.NewInt(-5), sk1)
	relation.AddStatement(b2Enc, pk2, b2, big.NewInt(1), nil)
	relation.AddStatement(b3Enc, pk3, b3, big.NewInt(3), nil)
	//err = relation.AddStatement(b4Enc, pk4, nil, big.NewInt(1), nil)
	//if err != nil {
	//	panic(err)
	//}
	elapse := time.Now()
	transferProof, _ := ProvePTransfer(relation)
	fmt.Println("prove time:", time.Since(elapse))
	return *transferProof
}
