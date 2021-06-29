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
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"math/big"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

// WithdrawProof in circuit
type WithdrawProofConstraints struct {
	// commitments
	Pt, Pa                          Point
	A_pk, A_TDivCRprime, A_Pt, A_Pa Point
	// response
	Z_rbar, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	CRangeProof ComRangeProofConstraints
	// common inputs
	CRStar                                 Point
	C                                      ElGamalEncConstraints
	BStar                                  Variable
	H, Ht, Ha, TDivCRprime, CLprimeInv, Pk Point
	Challenge                              Variable
	IsEnabled                              Variable
}

// define tests for verifying the withdraw proof
func (circuit *WithdrawProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	verifyWithdrawProof(cs, *circuit, params)

	return nil
}

/*
	verifyWithdrawProof verify the withdraw proof in circuit
	@cs: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func verifyWithdrawProof(
	cs *ConstraintSystem,
	proof WithdrawProofConstraints,
	params twistededwards.EdCurve,
) {
	// verify range proof first
	verifyComRangeProof(cs, proof.CRangeProof, params)

	// verify Ht
	verifyPt(cs, proof.Ht, proof.Pt, proof.A_Pt, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify Ha
	verifyPt(cs, proof.Ha, proof.Pa, proof.A_Pa, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify half enc
	verifyHalfEnc(cs, proof.H, proof.CRStar, proof.BStar, proof.IsEnabled, params)
	// verify balance
	verifyBalance(cs, proof.Pk, proof.A_pk, proof.CLprimeInv,
		proof.TDivCRprime, proof.A_TDivCRprime, proof.Challenge,
		proof.Z_sk, proof.Z_skInv, proof.Z_rbar, proof.IsEnabled, params)

}

/*
	verifyPt verify the tokenId proof
	@cs: the constraint system
	@Ht,Pt: public inputs
	@A_Pt: the random commitment
	@z_tsk: the response value
	@params: params for the curve tebn254
*/
func verifyPt(
	cs *ConstraintSystem,
	Ht, Pt, A_Pt Point,
	c Variable,
	z_tsk Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l, r Point
	l.ScalarMulNonFixedBase(cs, &Ht, z_tsk, params)
	r.ScalarMulNonFixedBase(cs, &Pt, c, params)
	r.AddGeneric(cs, &A_Pt, &r, params)
	IsPointEqual(cs, isEnabled, l, r)
}

/*
	verifyHalfEnc verify the C_L^{\star}
	@cs: the constraint system
	@pk,CLStar: public inputs
	@A_CLStar: the random commitment
	@z_r: the response value
	@params: params for the curve tebn254
*/
func verifyHalfEnc(
	cs *ConstraintSystem,
	h Point,
	CRStar Point,
	bStar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l Point
	hNeg := Neg(cs, h, params)
	l.ScalarMulNonFixedBase(cs, hNeg, bStar, params)
	IsPointEqual(cs, isEnabled, l, CRStar)
}

/*
	verifyBalance verify the remaining balance is positive
	@cs: the constraint system
	@pk,CLprimeInv,TDivCRprime: public inputs
	@A_pk,A_TDivCRprime: the random commitment
	@z_sk, z_skInv, z_rbar: the response value
	@params: params for the curve tebn254
*/
func verifyBalance(
	cs *ConstraintSystem,
	pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime Point,
	c Variable,
	z_sk, z_skInv, z_rbar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify pk = g^{sk}
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_sk, params)
	r1.ScalarMulNonFixedBase(cs, &pk, c, params)
	r1.AddGeneric(cs, &A_pk, &r1, params)
	IsPointEqual(cs, isEnabled, l1, r1)

	var g_zrbar, l2, r2 Point
	// verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	g_zrbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rbar, params)
	l2.ScalarMulNonFixedBase(cs, &CLprimeInv, z_skInv, params)
	l2.AddGeneric(cs, &g_zrbar, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &TDivCRprime, c, params)
	r2.AddGeneric(cs, &A_TDivCRprime, &r2, params)
	IsPointEqual(cs, isEnabled, l2, r2)
}

// set the witness for withdraw proof
func setWithdrawProofWitness(proof *zecrey.WithdrawProof, isEnabled bool) (witness WithdrawProofConstraints, err error) {
	if proof == nil {
		return witness, err
	}

	if proof.BStar.Cmp(big.NewInt(0)) >= 0 {
		return witness, ErrInvalidBStar
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		return witness, err
	}
	if !verifyRes {
		return witness, ErrInvalidProof
	}

	// generate the challenge
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	buf.Write(proof.Pt.Marshal())
	buf.Write(proof.Ha.Marshal())
	buf.Write(proof.Pa.Marshal())
	buf.Write(proof.C.CL.Marshal())
	buf.Write(proof.C.CR.Marshal())
	buf.Write(proof.CRStar.Marshal())
	buf.Write(proof.T.Marshal())
	buf.Write(proof.Pk.Marshal())
	buf.Write(proof.A_pk.Marshal())
	buf.Write(proof.A_TDivCRprime.Marshal())

	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return witness, err
	}
	// check challenge
	if !ffmath.Equal(c, proof.Challenge) {
		return witness, ErrInvalidChallenge
	}

	witness.Challenge.Assign(c.String())

	// commitments
	witness.Pt, err = SetPointWitness(proof.Pt)
	if err != nil {
		return witness, err
	}
	witness.Pa, err = SetPointWitness(proof.Pa)
	if err != nil {
		return witness, err
	}
	witness.A_pk, err = SetPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.A_TDivCRprime, err = SetPointWitness(proof.A_TDivCRprime)
	if err != nil {
		return witness, err
	}
	witness.A_Pt, err = SetPointWitness(proof.A_Pt)
	if err != nil {
		return witness, err
	}
	witness.A_Pa, err = SetPointWitness(proof.A_Pa)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_rbar.Assign(proof.Z_rbar.String())
	witness.Z_sk.Assign(proof.Z_sk.String())
	witness.Z_skInv.Assign(proof.Z_skInv.String())
	// Commitment Range Proofs
	witness.CRangeProof, err = setComRangeProofWitness(proof.CRangeProof, true)
	if err != nil {
		return witness, err
	}
	// common inputs
	witness.C, err = SetElGamalEncWitness(proof.C)
	if err != nil {
		return witness, err
	}
	witness.CRStar, err = SetPointWitness(proof.CRStar)
	if err != nil {
		return witness, err
	}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.Ht, err = SetPointWitness(proof.Ht)
	if err != nil {
		return witness, err
	}
	witness.Ha, err = SetPointWitness(proof.Ha)
	if err != nil {
		return witness, err
	}
	witness.TDivCRprime, err = SetPointWitness(proof.TDivCRprime)
	if err != nil {
		return witness, err
	}
	witness.CLprimeInv, err = SetPointWitness(proof.CLprimeInv)
	if err != nil {
		return witness, err
	}
	witness.Pk, err = SetPointWitness(proof.Pk)
	if err != nil {
		return witness, err
	}
	bStarNeg := new(big.Int).Neg(proof.BStar)
	witness.BStar.Assign(bStarNeg)
	if isEnabled {
		witness.IsEnabled.Assign(1)
	} else {
		witness.IsEnabled.Assign(0)
	}
	return witness, nil
}
