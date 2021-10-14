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
	// common inputs
	BStar1                                   Variable
	BStar2                                   Variable
	Fee                                      Variable
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

	// verify Ht
	verifyPt(cs, proof.Ht1, proof.Pt1, proof.A_Pt1, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	verifyPt(cs, proof.Ht2, proof.Pt2, proof.A_Pt2, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify correct enc
	verifyCorrectEnc1(cs, proof.H, proof.Pk, proof.ReceiverPk, proof.CStar, proof.ReceiverCStar, proof.BStar1, proof.Fee, proof.RStar, proof.IsEnabled, params)
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

	// verify Ht
	verifyPt(cs, proof.Ht1, proof.Pt1, proof.A_Pt1, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	verifyPt(cs, proof.Ht2, proof.Pt2, proof.A_Pt2, proof.Challenge, proof.Z_sk, proof.IsEnabled, params)
	// verify correct enc
	verifyCorrectEnc2(cs, proof.H, proof.Pk, proof.ReceiverPk, proof.CStar, proof.ReceiverCStar, proof.BStar2, proof.RStar, proof.IsEnabled, params)
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
func verifyCorrectEnc1(
	cs *ConstraintSystem,
	h, pk Point,
	receiverPk Point,
	CStar ElGamalEncConstraints,
	receiverCStar ElGamalEncConstraints,
	bStar Variable,
	fee Variable,
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
	deltaBalance := cs.Add(bStar, fee)
	CR.ScalarMulNonFixedBase(cs, hNeg, deltaBalance, params)
	CR.AddGeneric(cs, &gr, &CR, params)

	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, CStar)

	// check receiver
	CL.ScalarMulNonFixedBase(cs, &receiverPk, rStar, params)
	CR.ScalarMulNonFixedBase(cs, &h, deltaBalance, params)
	CR.AddGeneric(cs, &gr, &CR, params)
	IsElGamalEncEqual(cs, isEnabled, ElGamalEncConstraints{CL: CL, CR: CR}, receiverCStar)
}

/*
	verifyCorrectEnc verify the encryption
	@cs: the constraint system
	@h,pk,CStar: public inputs
	@bStar: the value
	@rStar: the random value
	@params: params for the curve tebn254
*/
func verifyCorrectEnc2(
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

