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

// SwapProof in circuit
type SwapProofConstraints struct {
	ProofPart1 SwapProofPartConstraints
	ProofPart2 SwapProofPartConstraints
}

type SwapProofPartConstraints struct {
	// commitments
	Pt1                               Point
	Pt2                               Point
	A_pk, A_TDivCRprime, A_Pt1, A_Pt2 Point
	// response
	Z_rbar, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	RangeProof ComRangeProofConstraints
	// common inputs
	BStar1                                   Variable
	BStar2                                   Variable
	RStar                                    Variable
	CStar                                    ElGamalEncConstraints
	C                                        ElGamalEncConstraints
	ReceiverCStar                            ElGamalEncConstraints
	ReceiverC                                ElGamalEncConstraints
	ReceiverPk                               Point
	H, Ht1, Ht2, TDivCRprime, CLprimeInv, Pk Point
	Challenge                                Variable
	IsEnabled                                Variable
}

// define tests for verifying the swap proof
func (circuit *SwapProofConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	VerifySwapProof(cs, *circuit, params)

	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@cs: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifySwapProof(
	cs *ConstraintSystem,
	proof SwapProofConstraints,
	params twistededwards.EdCurve,
) {
	cs.AssertIsEqual(proof.ProofPart1.BStar1, proof.ProofPart2.BStar1)
	cs.AssertIsEqual(proof.ProofPart1.BStar2, proof.ProofPart2.BStar2)
	// verify swap proof part
	VerifySwapProofPart1(cs, proof.ProofPart1, params)
	VerifySwapProofPart2(cs, proof.ProofPart2, params)
}

func VerifySwapProofPart1(
	cs *ConstraintSystem,
	proof SwapProofPartConstraints,
	params twistededwards.EdCurve,
) {
	// verify range proof first
	verifyComRangeProof(cs, proof.RangeProof, params)

	// verify Ht
	verifyPt(cs, proof.Ht1, proof.Pt1, proof.A_Pt1, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	verifyPt(cs, proof.Ht2, proof.Pt2, proof.A_Pt2, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify correct enc
	verifyCorrectEnc(cs, proof.H, proof.Pk, proof.ReceiverPk, proof.CStar, proof.ReceiverCStar, proof.BStar1, proof.RStar, proof.IsEnabled, params)
	// verify balance
	verifyBalance(cs, proof.Pk, proof.A_pk, proof.CLprimeInv,
		proof.TDivCRprime, proof.A_TDivCRprime, proof.Challenge,
		proof.Z_sk, proof.Z_skInv, proof.Z_rbar, proof.IsEnabled, params)
}

func VerifySwapProofPart2(
	cs *ConstraintSystem,
	proof SwapProofPartConstraints,
	params twistededwards.EdCurve,
) {
	// verify range proof first
	verifyComRangeProof(cs, proof.RangeProof, params)

	// verify Ht
	verifyPt(cs, proof.Ht1, proof.Pt1, proof.A_Pt1, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	verifyPt(cs, proof.Ht2, proof.Pt2, proof.A_Pt2, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify correct enc
	verifyCorrectEnc(cs, proof.H, proof.Pk, proof.ReceiverPk, proof.CStar, proof.ReceiverCStar, proof.BStar2, proof.RStar, proof.IsEnabled, params)
	// verify balance
	verifyBalance(cs, proof.Pk, proof.A_pk, proof.CLprimeInv,
		proof.TDivCRprime, proof.A_TDivCRprime, proof.Challenge,
		proof.Z_sk, proof.Z_skInv, proof.Z_rbar, proof.IsEnabled, params)
}

/*
	verifyCorrectEnc verify the encryption
	@cs: the constraint system
	@h,pk,CStar: public inputs
	@bStar: the value
	@rStar: the random value
	@params: params for the curve tebn254
*/
func verifyCorrectEnc(
	cs *ConstraintSystem,
	h, pk Point,
	receiverPk Point,
	CStar ElGamalEncConstraints,
	receiverCStar ElGamalEncConstraints,
	bStar Variable,
	rStar Variable,
	isEnabled Variable,
	params twistededwards.EdCurve,
) {
	// check sender
	var CL, CR, gr Point
	// C_L = pk^r
	CL.ScalarMulNonFixedBase(cs, &pk, rStar, params)
	// C_R = g^r h^b
	gr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, rStar, params)
	hNeg := Neg(cs, h, params)
	CR.ScalarMulNonFixedBase(cs, hNeg, bStar, params)
	CR.AddGeneric(cs, &gr, &CR, params)

	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, CStar)

	// check receiver
	CL.ScalarMulNonFixedBase(cs, &receiverPk, rStar, params)
	CR.ScalarMulNonFixedBase(cs, &h, bStar, params)
	CR.AddGeneric(cs, &gr, &CR, params)
	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, receiverCStar)
}

func SetSwapProofWitness(proof *zecrey.SwapProof, isEnabled bool) (witness SwapProofConstraints, err error) {
	part1, err := setSwapProofPartWitness(proof.ProofPart1, isEnabled)
	if err != nil {
		return witness, err
	}
	part2, err := setSwapProofPartWitness(proof.ProofPart2, isEnabled)
	if err != nil {
		return witness, err
	}
	witness.ProofPart1 = part1
	witness.ProofPart2 = part2
	return witness, nil
}

// set the witness for withdraw proof
func setSwapProofPartWitness(proof *zecrey.SwapProofPart, isEnabled bool) (witness SwapProofPartConstraints, err error) {
	if proof == nil {
		return witness, err
	}

	if proof.BStar1.Cmp(big.NewInt(0)) <= 0 || proof.BStar2.Cmp(big.NewInt(0)) <= 0 {
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
	buf.Write(proof.Ht1.Marshal())
	buf.Write(proof.Pt1.Marshal())
	buf.Write(proof.Ht2.Marshal())
	buf.Write(proof.Pt2.Marshal())
	buf.Write(proof.C.CL.Marshal())
	buf.Write(proof.C.CR.Marshal())
	buf.Write(proof.CStar.CL.Marshal())
	buf.Write(proof.CStar.CR.Marshal())
	buf.Write(proof.T.Marshal())
	buf.Write(proof.Pk.Marshal())
	buf.Write(proof.BStar1.Bytes())
	buf.Write(proof.BStar2.Bytes())
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
	witness.Pt1, err = SetPointWitness(proof.Pt1)
	if err != nil {
		return witness, err
	}
	witness.Pt2, err = SetPointWitness(proof.Pt2)
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
	witness.A_Pt1, err = SetPointWitness(proof.A_Pt1)
	if err != nil {
		return witness, err
	}
	witness.A_Pt2, err = SetPointWitness(proof.A_Pt2)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_rbar.Assign(proof.Z_rbar.String())
	witness.Z_sk.Assign(proof.Z_sk.String())
	witness.Z_skInv.Assign(proof.Z_skInv.String())
	// Commitment Range Proofs
	witness.RangeProof, err = setComRangeProofWitness(proof.RangeProof, true)
	if err != nil {
		return witness, err
	}
	// common inputs
	witness.C, err = SetElGamalEncWitness(proof.C)
	if err != nil {
		return witness, err
	}
	witness.CStar, err = SetElGamalEncWitness(proof.CStar)
	if err != nil {
		return witness, err
	}
	witness.ReceiverC, err = SetElGamalEncWitness(proof.ReceiverC)
	if err != nil {
		return witness, err
	}
	witness.ReceiverCStar, err = SetElGamalEncWitness(proof.ReceiverCStar)
	if err != nil {
		return witness, err
	}
	witness.ReceiverPk, err = SetPointWitness(proof.ReceiverPk)
	if err != nil {
		return witness, err
	}
	witness.H, err = SetPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.Ht1, err = SetPointWitness(proof.Ht1)
	if err != nil {
		return witness, err
	}
	witness.Ht2, err = SetPointWitness(proof.Ht2)
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
	witness.BStar1.Assign(proof.BStar1)
	witness.BStar2.Assign(proof.BStar2)
	witness.RStar.Assign(proof.RStar)
	if isEnabled {
		witness.IsEnabled.Assign(1)
	} else {
		witness.IsEnabled.Assign(0)
	}
	return witness, nil
}
