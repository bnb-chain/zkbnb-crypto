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

package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type TransferProofConstraints struct {
	// sub proofs
	SubProofs [NbTransferCount]TransferSubProofConstraints
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum Point
	Z_sum Variable
	// challenges
	C1, C2    Variable
	G, H      Point
	Fee       Variable
	IsEnabled Variable
}

/*
	TransferSubProofConstraints describes transfer proof in circuit
*/
type TransferSubProofConstraints struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_Y1, A_Y2, A_T, A_pk, A_TDivCPrime Point
	// respond values
	Z_r, Z_bDelta, Z_rstar1, Z_rstar2, Z_bstar1, Z_bstar2, Z_rbar, Z_bprime, Z_sk, Z_skInv Variable
	// range proof
	BStarRangeProof CtRangeProofConstraints
	// common inputs
	// original balance enc
	C ElGamalEncConstraints
	// delta balance enc
	CDelta ElGamalEncConstraints
	// new pedersen commitment for new balance
	T Point
	// new pedersen commitment for deleta balance or new balance
	Y Point
	// public key
	Pk Point
}

// define for testing transfer proof
func (circuit TransferProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}
	VerifyTransferProof(cs, circuit, params, hFunc)
	return nil
}

/*
	VerifyTransferProof verifys the privacy transfer proof
	@cs: the constraint system
	@proof: the transfer proof
	@params: params for the curve tebn254
*/
func VerifyTransferProof(
	cs *ConstraintSystem,
	proof TransferProofConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
) {
	CR_sum := zeroPoint(cs)
	// write public statements into buf
	writePointIntoBuf(&hFunc, proof.G)
	writePointIntoBuf(&hFunc, proof.H)
	// write into buf
	writePointIntoBuf(&hFunc, proof.A_sum)
	for _, subProof := range proof.SubProofs {
		// write common inputs into buf
		writeEncIntoBuf(&hFunc, subProof.C)
		writeEncIntoBuf(&hFunc, subProof.CDelta)
		writePointIntoBuf(&hFunc, subProof.Y)
		writePointIntoBuf(&hFunc, subProof.T)
		writePointIntoBuf(&hFunc, subProof.Pk)
		// write into buf
		writePointIntoBuf(&hFunc, subProof.A_CLDelta)
		writePointIntoBuf(&hFunc, subProof.A_CRDelta)
		CR_sum.AddGeneric(cs, &CR_sum, &subProof.CDelta.CR, params)
		// verify range proof params
		IsPointEqual(cs, proof.IsEnabled, subProof.BStarRangeProof.A, subProof.Y)
		// verify range proof
		rangeHFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, cs)
		if err != nil {
			log.Println("[VerifyTransferProof] err hash function:", err)
			return
		}
		verifyCtRangeProof(cs, subProof.BStarRangeProof, params, rangeHFunc)
	}
	c := hFunc.Sum()
	// TODO need to check XOR, cs.XOR bug exists
	//cCheck := cs.Xor(proof.C1, proof.C2)
	//IsVariableEqual(cs, proof.IsEnabled, c, cCheck)
	// verify sum proof
	var lSum, rSum Point
	lSum.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, proof.Z_sum, params)
	rSum.ScalarMulNonFixedBase(cs, &proof.H, proof.Fee, params)
	rSum.AddGeneric(cs, &CR_sum, &rSum, params)
	rSum.ScalarMulNonFixedBase(cs, &rSum, c, params)
	rSum.AddGeneric(cs, &proof.A_sum, &rSum, params)
	IsPointEqual(cs, proof.IsEnabled, lSum, rSum)
	// Verify sub proofs
	for _, subProof := range proof.SubProofs {
		// Verify valid enc
		verifyValidEnc(
			cs,
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, proof.H, subProof.CDelta.CR, subProof.A_CRDelta,
			c,
			subProof.Z_r, subProof.Z_bDelta,
			proof.IsEnabled,
			params,
		)
		// define variables
		var (
			CPrime, CPrimeNeg ElGamalEncConstraints
		)
		// set CPrime & CPrimeNeg
		CPrime = encAdd(cs, subProof.C, subProof.CDelta, params)
		CPrimeNeg = negElgamal(cs, CPrime)
		// verify Y_1 = g^{r_i^{\star}} h^{b_i^{\Delta}}
		var l1, h_z_bstar1, r1 Point
		l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.Z_rstar1, params)
		h_z_bstar1.ScalarMulNonFixedBase(cs, &proof.H, subProof.Z_bstar1, params)
		l1.AddGeneric(cs, &l1, &h_z_bstar1, params)
		r1.ScalarMulNonFixedBase(cs, &subProof.Y, proof.C1, params)
		r1.AddGeneric(cs, &r1, &subProof.A_Y1, params)
		IsPointEqual(cs, proof.IsEnabled, l1, r1)
		// Verify ownership
		var h_z_bprime, l2, h_z_bstar2, r2 Point
		h_z_bprime.ScalarMulNonFixedBase(cs, &proof.H, subProof.Z_bprime, params)
		// Y_2 = g^{r_{i}^{\star}} h^{b_i'}
		l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.Z_rstar2, params)
		h_z_bstar2.ScalarMulNonFixedBase(cs, &proof.H, subProof.Z_bstar2, params)
		l2.AddGeneric(cs, &l2, &h_z_bstar2, params)
		r2.ScalarMulNonFixedBase(cs, &subProof.Y, proof.C2, params)
		r2.AddGeneric(cs, &r2, &subProof.A_Y2, params)
		IsPointEqual(cs, proof.IsEnabled, l2, r2)
		// T = g^{\bar{r}_i} h^{b'}
		var g_z_rbar, l3, r3 Point
		g_z_rbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.Z_rbar, params)
		l3.AddGeneric(cs, &g_z_rbar, &h_z_bprime, params)
		r3.ScalarMulNonFixedBase(cs, &subProof.T, proof.C2, params)
		r3.AddGeneric(cs, &r3, &subProof.A_T, params)
		IsPointEqual(cs, proof.IsEnabled, l3, r3)
		// pk = g^{sk}
		var l4, r4 Point
		l4.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.Z_sk, params)
		r4.ScalarMulNonFixedBase(cs, &subProof.Pk, proof.C2, params)
		r4.AddGeneric(cs, &r4, &subProof.A_pk, params)
		IsPointEqual(cs, proof.IsEnabled, l4, r4)
		// T_i = (C_R')/(C_L')^{sk^{-1}} g^{\bar{r}_i}
		var l5, r5 Point
		l5.ScalarMulNonFixedBase(cs, &CPrimeNeg.CL, subProof.Z_skInv, params)
		l5.AddGeneric(cs, &l5, &g_z_rbar, params)
		r5.AddGeneric(cs, &subProof.T, &CPrimeNeg.CR, params)
		r5.ScalarMulNonFixedBase(cs, &r5, proof.C2, params)
		r5.AddGeneric(cs, &r5, &subProof.A_TDivCPrime, params)
		IsPointEqual(cs, proof.IsEnabled, l5, r5)
	}
	return
}

/*
	verifyValidEnc verifys the encryption
	@cs: the constraint system
	@pk: the public key for the encryption
	@C_LDelta,C_RDelta: parts for the encryption
	@A_C_LDelta,A_CRDelta: random commitments
	@h: the generator
	@c: the challenge
	@z_r,z_bDelta: response values for valid enc proof
	@params: params for the curve tebn254
*/
func verifyValidEnc(
	cs *ConstraintSystem,
	pk, C_LDelta, A_CLDelta, h, C_RDelta, A_CRDelta Point,
	c Variable,
	z_r, z_bDelta Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	// pk^{z_r} == A_{C_L^{\Delta}} (C_L^{\Delta})^c
	var l1, r1 Point
	l1.ScalarMulNonFixedBase(cs, &pk, z_r, params)
	r1.ScalarMulNonFixedBase(cs, &C_LDelta, c, params)
	r1.AddGeneric(cs, &A_CLDelta, &r1, params)
	IsPointEqual(cs, isEnabled, l1, r1)

	// g^{z_r} h^{z_b^{\Delta}} == A_{C_R^{\Delta}} (C_R^{\Delta})^c
	var gzr, l2, r2 Point
	gzr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_r, params)
	l2.ScalarMulNonFixedBase(cs, &h, z_bDelta, params)
	l2.AddGeneric(cs, &gzr, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &C_RDelta, c, params)
	r2.AddGeneric(cs, &A_CRDelta, &r2, params)
	IsPointEqual(cs, isEnabled, l2, r2)
}

/*
	SetTransferProofWitness set witness for the privacy transfer proof
*/
func SetTransferProofWitness(proof *zecrey.TransferProof, isEnabled bool) (witness TransferProofConstraints, err error) {
	if proof == nil {
		return witness, ErrInvalidSetParams
	}
	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetTransferProofWitness] err info:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetTransferProofWitness] invalid proof")
		return witness, ErrInvalidProof
	}
	// A_sum
	witness.A_sum, err = SetPointWitness(proof.A_sum)
	if err != nil {
		return witness, err
	}
	// z_tsk
	witness.Z_sum.Assign(proof.Z_sum)
	// generator
	witness.G, err = SetPointWitness(proof.G)
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	// C = C1 \oplus C2
	witness.C1.Assign(proof.C1)
	witness.C2.Assign(proof.C2)
	// set fee
	witness.Fee.Assign(proof.Fee)
	// set sub proofs
	for i, subProof := range proof.SubProofs {
		// define var
		var subProofWitness TransferSubProofConstraints
		// set values
		// A_{C_L^{\Delta}}
		subProofWitness.A_CLDelta, err = SetPointWitness(subProof.A_CLDelta)
		if err != nil {
			return witness, err
		}
		// A_{C_R^{\Delta}}
		subProofWitness.A_CRDelta, err = SetPointWitness(subProof.A_CRDelta)
		if err != nil {
			return witness, err
		}
		subProofWitness.A_Y1, err = SetPointWitness(subProof.A_Y1)
		if err != nil {
			return witness, err
		}
		subProofWitness.A_Y2, err = SetPointWitness(subProof.A_Y2)
		if err != nil {
			return witness, err
		}
		// A_T
		subProofWitness.A_T, err = SetPointWitness(subProof.A_T)
		if err != nil {
			return witness, err
		}
		// A_{pk}
		subProofWitness.A_pk, err = SetPointWitness(subProof.A_pk)
		if err != nil {
			return witness, err
		}
		// A_{T/C'}
		subProofWitness.A_TDivCPrime, err = SetPointWitness(subProof.A_TDivCPrime)
		if err != nil {
			return witness, err
		}
		// Z_r
		subProofWitness.Z_r.Assign(subProof.Z_r)
		// z_{b^{\Delta}}
		subProofWitness.Z_bDelta.Assign(subProof.Z_bDelta)
		// z_{r^{\star} - r}
		subProofWitness.Z_rstar1.Assign(subProof.Z_rstar1)
		subProofWitness.Z_rstar2.Assign(subProof.Z_rstar2)
		subProofWitness.Z_bstar1.Assign(subProof.Z_bstar1)
		subProofWitness.Z_bstar2.Assign(subProof.Z_bstar2)
		// z_{\bar{r}}
		subProofWitness.Z_rbar.Assign(subProof.Z_rbar)
		// z_{b'}
		subProofWitness.Z_bprime.Assign(subProof.Z_bprime)
		// z_{sk}
		subProofWitness.Z_sk.Assign(subProof.Z_sk)
		// z_{sk}
		subProofWitness.Z_skInv.Assign(subProof.Z_skInv)
		// range proof
		subProofWitness.BStarRangeProof, err = setCtRangeProofWitness(subProof.BStarRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		// C
		subProofWitness.C, err = SetElGamalEncWitness(subProof.C)
		if err != nil {
			return witness, err
		}
		// C^{\Delta}
		subProofWitness.CDelta, err = SetElGamalEncWitness(subProof.CDelta)
		if err != nil {
			return witness, err
		}
		// T
		subProofWitness.T, err = SetPointWitness(subProof.T)
		if err != nil {
			return witness, err
		}
		// Y
		subProofWitness.Y, err = SetPointWitness(subProof.Y)
		if err != nil {
			return witness, err
		}
		// Pk
		subProofWitness.Pk, err = SetPointWitness(subProof.Pk)
		if err != nil {
			return witness, err
		}
		// set into witness
		witness.SubProofs[i] = subProofWitness
	}
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}
