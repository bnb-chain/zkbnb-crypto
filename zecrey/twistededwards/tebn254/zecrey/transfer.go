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
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/util"
	"log"
	"math/big"
)

func ProveTransfer(relation *TransferProofRelation) (proof *TransferProof, err error) {
	if relation == nil || relation.Statements == nil || len(relation.Statements) != TransferSubProofCount {
		log.Println("[ProveTransfer] invalid params")
		return nil, ErrInvalidParams
	}
	relation.R_sum = ffmath.Mod(relation.R_sum, Order)
	// Verify \sum b_i^{\Delta} + fee = 0
	sum := int64(0)
	for _, statement := range relation.Statements {
		sum = sum + statement.BDelta
	}
	sum = sum + int64(relation.GasFee)
	// statements must be correct
	if sum != 0 {
		log.Println("[ProveTransfer] invalid params")
		return nil, ErrInvalidParams
	}
	var (
		A_sum            *Point
		alpha_r_sum      *big.Int
		RStars           [TransferSubProofCount]*big.Int
		Ys               [TransferSubProofCount]*Point
		BStarRangeProofs [TransferSubProofCount]*RangeProof
		commitEntities   = make([]*transferCommitValues, TransferSubProofCount)
		buf              bytes.Buffer
		rangechan        = make(chan int, TransferSubProofCount)
	)
	// initialize range proofs
	for i := 0; i < TransferSubProofCount; i++ {
		RStars[i] = new(big.Int)
		BStarRangeProofs[i] = new(RangeProof)
	}
	// construct range proofs
	for i, statement := range relation.Statements {
		go proveCtRangeRoutine(int64(statement.BStar), G, H, RStars[i], BStarRangeProofs[i], rangechan)
	}
	// wait for receiving the range proof
	for i := 0; i < len(relation.Statements); i++ {
		val := <-rangechan
		if val == ErrCode {
			log.Println("[ProveTransfer] err: unable to make the range proof")
			return nil, errors.New("[ProveTransfer] err: unable to make the range proof")
		}
	}
	// set Ys
	for i, BStarRangeProof := range BStarRangeProofs {
		Ys[i] = new(Point).Set(BStarRangeProof.A)
	}
	// initialize proof
	proof = new(TransferProof)
	// add Pt,G,Waste from relation
	proof.GasFee = relation.GasFee
	proof.AssetId = relation.AssetId
	// write public statements into buf
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	// construct for A_sum
	alpha_r_sum = curve.RandomValue()
	A_sum = curve.ScalarMul(G, alpha_r_sum)
	// write into buf
	writePointIntoBuf(&buf, A_sum)
	var (
		ownershipChan = make(chan int, 1)
	)
	for i, statement := range relation.Statements {
		// write common inputs into buf
		writeEncIntoBuf(&buf, statement.C)
		writeEncIntoBuf(&buf, statement.CDelta)
		writePointIntoBuf(&buf, Ys[i])
		writePointIntoBuf(&buf, statement.T)
		writePointIntoBuf(&buf, statement.Pk)
		// define variables
		var (
			// common inputs
			C               = statement.C
			pk              = statement.Pk
			sk              = statement.Sk
			CDelta          = statement.CDelta
			Y               = Ys[i]
			BStarRangeProof = BStarRangeProofs[i]
		)
		// initialize commit values
		commitEntities[i] = new(transferCommitValues)
		// start Sigma protocol
		// commit enc values
		commitEntities[i].alpha_r, commitEntities[i].alpha_bDelta, commitEntities[i].A_CLDelta, commitEntities[i].A_CRDelta = commitValidEnc(pk, G, H)
		// write into buf
		writePointIntoBuf(&buf, commitEntities[i].A_CLDelta)
		writePointIntoBuf(&buf, commitEntities[i].A_CRDelta)
		// if user does not own the account, then commit bDelta.
		if sk == nil {
			commitEntities[i].alpha_rstar, commitEntities[i].A_Y1 = commitValidDelta(commitEntities[i].alpha_bDelta, G, H)
		} else { // Otherwise, commit ownership
			// commit to ownership
			go commitOwnershipRoutine(G, H, curve.Neg(curve.Add(C.CL, CDelta.CL)), commitEntities, i, ownershipChan)
		}
		// generate sub proofs
		commitValues := commitEntities[i]
		proof.SubProofs[i] = &TransferSubProof{
			A_CLDelta:       commitValues.A_CLDelta,
			A_CRDelta:       commitValues.A_CRDelta,
			A_Y1:            commitValues.A_Y1,
			A_Y2:            commitValues.A_Y2,
			A_T:             commitValues.A_T,
			BStarRangeProof: BStarRangeProof,
			// original balance enc
			C: statement.C,
			// delta balance enc
			CDelta: statement.CDelta,
			// new pedersen commitment for new balance
			T: statement.T,
			// new pedersen commitment for deleta balance or new balance
			Y: Y,
			// public key
			Pk: statement.Pk,
		}
	}
	// set A_sum
	proof.A_sum = A_sum
	// make sure the length of commitEntities and statements is equal
	if len(commitEntities) != len(relation.Statements) {
		log.Println("[ProveTransfer] err: invalid statements")
		return nil, ErrStatements
	}
	// challenge phase
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[ProveTransfer] err: unable to hash:", err)
		return nil, err
	}
	// random challenge for sim
	c1 := curve.RandomValue()
	c2 := ffmath.Xor(c, c1)
	proof.C1 = c1
	proof.C2 = c2
	// construct z_sum
	var (
		z_sum   *big.Int
		simChan = make(chan int, TransferSubProofCount-1)
	)
	// construct responses for sum proof
	z_sum = ffmath.AddMod(alpha_r_sum, ffmath.Multiply(c, relation.R_sum), Order)
	// set z_sum into proof
	proof.Z_sum = z_sum
	for i := 0; i < len(commitEntities); i++ {
		// define variables
		var (
			z_r, z_bDelta *big.Int
			Y             = Ys[i]
			RStar         = RStars[i]
			commitValues  = commitEntities[i]
			statement     = relation.Statements[i]
		)
		// construct responses for valid enc
		z_r, z_bDelta = respondValidEnc(
			statement.R, big.NewInt(statement.BDelta), commitValues.alpha_r, commitValues.alpha_bDelta, c,
		)
		// complete sub proofs
		proof.SubProofs[i].Z_r = z_r
		proof.SubProofs[i].Z_bDelta = z_bDelta
		// if the user does not own the account, run simOwnership
		if statement.Sk == nil {
			var (
				CPrime      *ElGamalEnc
				CPrimeNeg   *ElGamalEnc
				TCRprimeInv *Point
				z_rstar1    *big.Int
				z_bstar1    *big.Int
			)

			// construct z_rstar1
			z_rstar1 = ffmath.AddMod(commitValues.alpha_rstar, ffmath.Multiply(c1, RStar), Order)
			z_bstar1 = ffmath.AddMod(commitValues.alpha_bDelta, ffmath.Multiply(c1, big.NewInt(statement.BDelta)), Order)

			CPrime, err = twistedElgamal.EncAdd(statement.C, statement.CDelta)
			if err != nil {
				log.Println("[ProveTransfer] err info:", err)
				return nil, err
			}
			CPrimeNeg = negElgamal(CPrime)
			TCRprimeInv = curve.Add(statement.T, CPrimeNeg.CR)
			go simOwnershipRoutine(
				G, H, Y, statement.T, statement.Pk,
				TCRprimeInv, CPrimeNeg.CL,
				c2,
				proof, i,
				simChan,
			)
			// set proof
			proof.SubProofs[i].Z_rstar1 = z_rstar1
			proof.SubProofs[i].Z_bstar1 = z_bstar1
		} else { // otherwise, run simValidDelta
			j := <-ownershipChan
			if j != i {
				log.Println("[ProveTransfer] invalid params")
				return nil, ErrInvalidParams
			}
			var (
				A_Y1               *Point
				z_rstar1, z_bstar1 *big.Int
			)
			z_rstar1, z_bstar1, A_Y1 = simValidDelta(
				G, H,
				Y, c1,
			)
			z_rstar2, z_bstar2, z_rbar, z_bprime, z_sk, z_skInv := respondOwnership(
				RStars[i], statement.RBar, big.NewInt(int64(statement.BPrime)), statement.Sk,
				commitValues.alpha_rstar, commitValues.alpha_rbar,
				commitValues.alpha_bprime, commitValues.alpha_sk, commitValues.alpha_skInv, c2,
			)
			// complete sub proofs
			proof.SubProofs[i].A_Y1 = A_Y1
			proof.SubProofs[i].A_Y2 = commitValues.A_Y2
			proof.SubProofs[i].A_T = commitValues.A_T
			proof.SubProofs[i].A_pk = commitValues.A_pk
			proof.SubProofs[i].A_TDivCPrime = commitValues.A_TDivCPrime

			proof.SubProofs[i].Z_rbar = z_rbar
			proof.SubProofs[i].Z_bprime = z_bprime
			proof.SubProofs[i].Z_sk = z_sk
			proof.SubProofs[i].Z_skInv = z_skInv
			proof.SubProofs[i].Z_rstar1 = z_rstar1
			proof.SubProofs[i].Z_rstar2 = z_rstar2
			proof.SubProofs[i].Z_bstar1 = z_bstar1
			proof.SubProofs[i].Z_bstar2 = z_bstar2
		}
	}
	for i := 0; i < TransferSubProofCount-1; i++ {
		val := <-simChan
		if val == ErrCode {
			log.Println("[ProveTransfer] err code")
			return nil, errors.New("[ProveTransfer] err code")
		}
	}
	// response phase
	return proof, nil
}

/**
commit phase for R_{ValidDelta} = {Y/C_R^{\Delta} = g^{r^{\star} - r}}
@g: generator
*/
func commitValidDelta(alpha_bDelta *big.Int, g, h *Point) (alpha_rstar *big.Int, A_Y1 *Point) {
	alpha_rstar = curve.RandomValue()
	A_Y1 = curve.Add(curve.ScalarMul(g, alpha_rstar), curve.ScalarMul(h, alpha_bDelta))
	return
}

func (proof *TransferProof) Verify() (bool, error) {
	if !validUint64(proof.GasFee) {
		log.Println("[Verify TransferProof] invalid params")
		return false, errors.New("[Verify TransferProof] invalid params")
	}
	// generate the challenge
	var (
		CR_sum    = curve.ZeroPoint()
		c         *big.Int
		buf       bytes.Buffer
		err       error
		rangeChan = make(chan int, TransferSubProofCount)
	)
	// write public statements into buf
	buf.Write(PaddingBigIntBytes(FixedCurve))
	writeUint64IntoBuf(&buf, proof.GasFee)
	writeUint64IntoBuf(&buf, uint64(proof.AssetId))
	// write into buf
	writePointIntoBuf(&buf, proof.A_sum)
	for _, subProof := range proof.SubProofs {
		// write common inputs into buf
		writeEncIntoBuf(&buf, subProof.C)
		writeEncIntoBuf(&buf, subProof.CDelta)
		writePointIntoBuf(&buf, subProof.Y)
		writePointIntoBuf(&buf, subProof.T)
		writePointIntoBuf(&buf, subProof.Pk)
		// write into buf
		writePointIntoBuf(&buf, subProof.A_CLDelta)
		writePointIntoBuf(&buf, subProof.A_CRDelta)
		CR_sum = curve.Add(CR_sum, subProof.CDelta.CR)
		// verify range proof params
		if !subProof.BStarRangeProof.A.Equal(subProof.Y) {
			log.Println("[Verify TransferProof] invalid params")
			return false, errors.New("[Verify TransferProof] invalid params")
		}
		// verify range proof
		go verifyCtRangeRoutine(subProof.BStarRangeProof, rangeChan)
	}
	// c = hash()
	c, err = util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify TransferProof] err info:", err)
		return false, err
	}
	// Verify c
	cCheck := ffmath.Xor(proof.C1, proof.C2)
	if !ffmath.Equal(c, cCheck) {
		log.Println("[Verify TransferProof] invalid challenge")
		return false, ErrInvalidChallenge
	}
	// verify sum proof
	lSum := curve.ScalarMul(G, proof.Z_sum)
	rSum := curve.Add(
		proof.A_sum,
		curve.ScalarMul(
			curve.Add(CR_sum, curve.ScalarMul(H, big.NewInt(int64(proof.GasFee)))),
			c,
		),
	)
	if !lSum.Equal(rSum) {
		log.Println("[Verify TransferProof] lSum != rSum")
		return false, nil
	}
	// Verify sub proofs
	for _, subProof := range proof.SubProofs {
		// Verify valid enc
		validEncRes, err := verifyValidEnc(
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, G, H, subProof.CDelta.CR, subProof.A_CRDelta,
			c,
			subProof.Z_r, subProof.Z_bDelta,
		)
		if err != nil {
			log.Println("[Verify TransferProof] err verify valid enc:", err)
			return false, err
		}
		if !validEncRes {
			log.Println("[Verify TransferProof] err: invalid enc")
			return false, nil
		}
		// define variables
		var (
			h_z_bprime, g_z_rbar *Point
			CPrime, CPrimeNeg    *ElGamalEnc
		)
		// set CPrime & CPrimeNeg
		CPrime, err = twistedElgamal.EncAdd(subProof.C, subProof.CDelta)
		if err != nil {
			log.Println("[Verify TransferProof] err info:", err)
			return false, err
		}
		CPrimeNeg = negElgamal(CPrime)
		// verify Y_1 = g^{r_i^{\star}} h^{b_i^{\Delta}}
		l1 := curve.Add(
			curve.ScalarMul(G, subProof.Z_rstar1),
			curve.ScalarMul(H, subProof.Z_bstar1),
		)
		r1 := curve.Add(subProof.A_Y1, curve.ScalarMul(subProof.Y, proof.C1))
		if !l1.Equal(r1) {
			log.Println("[Verify TransferProof] l1 != r1")
			return false, nil
		}
		// Verify ownership
		h_z_bprime = curve.ScalarMul(H, subProof.Z_bprime)
		// Y_2 = g^{r_{i}^{\star}} h^{b_i'}
		l2 := curve.Add(
			curve.ScalarMul(G, subProof.Z_rstar2),
			curve.ScalarMul(H, subProof.Z_bstar2),
		)
		r2 := curve.Add(
			subProof.A_Y2,
			curve.ScalarMul(subProof.Y, proof.C2),
		)
		if !l2.Equal(r2) {
			log.Println("[Verify TransferProof] l2 != r2")
			return false, nil
		}
		// T = g^{\bar{r}_i} h^{b'}
		g_z_rbar = curve.ScalarMul(G, subProof.Z_rbar)
		l3 := curve.Add(
			g_z_rbar,
			h_z_bprime,
		)
		r3 := curve.Add(
			subProof.A_T,
			curve.ScalarMul(subProof.T, proof.C2),
		)
		if !l3.Equal(r3) {
			log.Println("[Verify TransferProof] l3 != r3")
			return false, nil
		}
		// pk = g^{sk}
		l4 := curve.ScalarMul(G, subProof.Z_sk)
		r4 := curve.Add(
			subProof.A_pk,
			curve.ScalarMul(subProof.Pk, proof.C2),
		)
		if !l4.Equal(r4) {
			log.Println("[Verify TransferProof] l4 != r4")
			return false, nil
		}
		// T_i = (C_R')/(C_L')^{sk^{-1}} g^{\bar{r}_i}
		l5 := curve.Add(
			curve.ScalarMul(CPrimeNeg.CL, subProof.Z_skInv),
			g_z_rbar,
		)
		r5 := curve.Add(
			subProof.A_TDivCPrime,
			curve.ScalarMul(
				curve.Add(subProof.T, CPrimeNeg.CR),
				proof.C2,
			),
		)
		if !l5.Equal(r5) {
			log.Println("[Verify TransferProof] l5 != r5")
			return false, nil
		}
	}
	for i := 0; i < TransferSubProofCount; i++ {
		val := <-rangeChan
		if val == ErrCode {
			return false, errors.New("[Verify TransferProof] invalid range proof")
		}
	}
	return true, nil
}

func simValidDelta(
	g, h *Point,
	Y *Point, cSim *big.Int,
) (
	z_rstar1, z_bstar1 *big.Int, A_Y1 *Point,
) {
	z_rstar1 = curve.RandomValue()
	z_bstar1 = curve.RandomValue()
	h_z_bDelta := curve.ScalarMul(h, z_bstar1)
	g_z_rstar := curve.ScalarMul(g, z_rstar1)
	A_Y1 = curve.Add(
		g_z_rstar,
		curve.Add(
			h_z_bDelta,
			curve.ScalarMul(curve.Neg(Y), cSim),
		),
	)
	return z_rstar1, z_bstar1, A_Y1
}

func respondOwnership(
	rstar, rbar, bprime, sk,
	alpha_rstar, alpha_rbar, alpha_bprime, alpha_sk, alpha_skInv, c *big.Int,
) (
	z_rstar2, z_bstar2, z_rbar, z_bprime, z_sk, z_skInv *big.Int,
) {
	z_rbar = ffmath.AddMod(alpha_rbar, ffmath.Multiply(c, rbar), Order)
	z_bprime = ffmath.AddMod(alpha_bprime, ffmath.Multiply(c, bprime), Order)
	z_bstar2 = z_bprime
	z_rstar2 = ffmath.AddMod(alpha_rstar, ffmath.Multiply(c, rstar), Order)
	skInv := ffmath.ModInverse(sk, Order)
	z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, skInv), Order)
	return
}

/**
commitOwnershipRoutine: commit phase for R_{Ownership} = {
Y/T = g^{r^{\star} - \bar{r}} \wedge
T = g^{\bar{r}} h^{b'} \wedge
pk = g^{sk} \wedge
T(C_R + C_R^{\Delta})^{-1} = [(C_L + C_L^{\Delta})^{-1}]^{sk^{-1}} g^{\bar{r}}}
@g: generator
@h: generator
@hDec: (C_L + C_L^{\Delta})^{-1}
*/
func commitOwnershipRoutine(g, h, hDec *Point, commitEntities []*transferCommitValues, i int, ownershipChan chan int) {
	commitEntities[i].alpha_rstar = curve.RandomValue()
	commitEntities[i].alpha_rbar = curve.RandomValue()
	commitEntities[i].alpha_bprime = curve.RandomValue()
	commitEntities[i].alpha_sk = curve.RandomValue()
	commitEntities[i].alpha_skInv = ffmath.ModInverse(commitEntities[i].alpha_sk, Order)
	h_alpha_bprime := curve.ScalarMul(h, commitEntities[i].alpha_bprime)
	g_alpha_rbar := curve.ScalarMul(g, commitEntities[i].alpha_rbar)
	commitEntities[i].A_Y2 = curve.Add(curve.ScalarMul(g, commitEntities[i].alpha_rstar), h_alpha_bprime)
	commitEntities[i].A_T = curve.Add(g_alpha_rbar, h_alpha_bprime)
	commitEntities[i].A_pk = curve.ScalarMul(g, commitEntities[i].alpha_sk)
	commitEntities[i].A_TDivCPrime = curve.Add(curve.ScalarMul(hDec, commitEntities[i].alpha_skInv), g_alpha_rbar)
	ownershipChan <- i
}

func simOwnershipRoutine(
	g, h, Y, T, pk, TCRprimeInv, CLprimeInv *Point,
	cSim *big.Int,
	proof *TransferProof, i int,
	simChan chan int,
) {
	proof.SubProofs[i].Z_rbar, proof.SubProofs[i].Z_bprime, proof.SubProofs[i].Z_sk, proof.SubProofs[i].Z_skInv, proof.SubProofs[i].Z_rstar2, proof.SubProofs[i].Z_bstar2 =
		curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue(), curve.RandomValue()
	// A_{Y/T} = g^{z_{r^{\star} - \bar{r}}} (Y T^{-1})^{-c}
	g_z_rstar := curve.ScalarMul(g, proof.SubProofs[i].Z_rstar2)
	proof.SubProofs[i].A_Y2 = curve.Add(
		g_z_rstar,
		curve.Add(
			curve.ScalarMul(h, proof.SubProofs[i].Z_bstar2),
			curve.ScalarMul(curve.Neg(Y), cSim),
		),
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

/**
commit phase for R_{ValidEnc} = {C_L = pk^r \wedge C_R = g^r h^{b}}
@pk: public key
@g: generator
@h: generator
*/
func commitValidEnc(pk, g, h *Point) (
	alpha_r, alpha_bDelta *big.Int, A_CLDelta, A_CRDelta *Point,
) {
	alpha_r = curve.RandomValue()
	alpha_bDelta = curve.RandomValue()
	A_CLDelta = curve.ScalarMul(pk, alpha_r)
	A_CRDelta = curve.Add(curve.ScalarMul(g, alpha_r), curve.ScalarMul(h, alpha_bDelta))
	return
}

func respondValidEnc(r, bDelta, alpha_r, alpha_bDelta, c *big.Int) (
	z_r, z_bDelta *big.Int,
) {
	z_r = ffmath.AddMod(alpha_r, ffmath.Multiply(c, r), Order)
	z_bDelta = ffmath.AddMod(alpha_bDelta, ffmath.Multiply(c, bDelta), Order)
	return
}

/*
	verifyValidEnc verifys the encryption
	@pk: the public key for the encryption
	@C_LDelta,C_RDelta: parts for the encryption
	@A_C_LDelta,A_CRDelta: random commitments
	@h: the generator
	@c: the challenge
	@z_r,z_bDelta: response values for valid enc proof
*/
func verifyValidEnc(
	pk, C_LDelta, A_CLDelta, g, h, C_RDelta, A_CRDelta *Point,
	c *big.Int,
	z_r, z_bDelta *big.Int,
) (bool, error) {
	// pk^{z_r} == A_{C_L^{\Delta}} (C_L^{\Delta})^c
	l1 := curve.ScalarMul(pk, z_r)
	r1 := curve.Add(A_CLDelta, curve.ScalarMul(C_LDelta, c))
	if !l1.Equal(r1) {
		return false, nil
	}

	// g^{z_r} h^{z_b^{\Delta}} == A_{C_R^{\Delta}} (C_R^{\Delta})^c
	l2 := curve.Add(curve.ScalarMul(g, z_r), curve.ScalarMul(h, z_bDelta))
	r2 := curve.Add(A_CRDelta, curve.ScalarMul(C_RDelta, c))
	return l2.Equal(r2), nil
}
