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
	"errors"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
)

type TransferProofConstraints struct {
	// sub proofs
	SubProofs [NbTransferCount]TransferSubProofConstraints
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum Point
	Z_sum Variable
	// challenges
	C1, C2            Variable
	GasFee            Variable
	C_fee_DeltaForGas ElGamalEncConstraints
	AssetId           Variable
	IsEnabled         Variable
}

/*
	TransferSubProofConstraints describes transfer proof in circuit
*/
type TransferSubProofConstraints struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_Y1, A_Y2, A_T, A_pk, A_TDivCPrime Point
	// respond values
	Z_r, Z_bDelta, Z_rstar1, Z_rstar2, Z_bstar1, Z_bstar2, Z_bar_r, Z_bprime, Z_sk, Z_skInv Variable
	// range proof
	//BStarRangeProof CtRangeProofConstraints
	// common inputs
	// original balance Enc
	C ElGamalEncConstraints
	// delta balance Enc
	CDelta ElGamalEncConstraints
	// new pedersen commitment for new balance
	T Point
	// new pedersen commitment for deleta balance or new balance
	Y Point
	// public key
	Pk Point
}

// define for testing transfer proof
func (circuit TransferProofConstraints) Define(api API) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	// verify H
	H := Point{
		X: HX,
		Y: HY,
	}
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tool := NewEccTool(api, params)
	VerifyTransferProof(tool, api, &circuit, hFunc, H)
	return nil
}

/*
	VerifyTransferProof verifys the privacy transfer proof
	@api: the constraint system
	@proof: the transfer proof
	@params: params for the curve tebn254
*/
func VerifyTransferProof(
	tool *EccTool,
	api API,
	proof *TransferProofConstraints,
	hFunc MiMC,
	h Point,
) (c2 Variable, pkProofs [MaxRangeProofCount]CommonPkProof, tProofs [MaxRangeProofCount]CommonTProof) {
	CR_sum := zeroPoint(api)
	// write public statements into buf
	hFunc.Write(FixedCurveParam(api))
	// write into buf
	hFunc.Write(proof.GasFee)
	hFunc.Write(proof.AssetId)
	WritePointIntoBuf(&hFunc, proof.A_sum)
	for _, subProof := range proof.SubProofs {
		// write common inputs into buf
		WriteEncIntoBuf(&hFunc, subProof.C)
		WriteEncIntoBuf(&hFunc, subProof.CDelta)
		WritePointIntoBuf(&hFunc, subProof.Y)
		WritePointIntoBuf(&hFunc, subProof.T)
		WritePointIntoBuf(&hFunc, subProof.Pk)
		// write into buf
		WritePointIntoBuf(&hFunc, subProof.A_CLDelta)
		WritePointIntoBuf(&hFunc, subProof.A_CRDelta)
		CR_sum = tool.Add(CR_sum, subProof.CDelta.CR)
		// verify range proof params
		//IsPointEqual(api, proof.IsEnabled, subProof.BStarRangeProof.A, subProof.Y)
		// verify range proof
		//rangeHFunc, err := mimc.NewMiMC(zmimc.SEED, params.ID, api)
		//if err != nil {
		//	log.Println("[VerifyTransferProof] err hash function:", err)
		//	return
		//}
		//VerifyCtRangeProof(api, subProof.BStarRangeProof, params, rangeHFunc)
	}
	c := hFunc.Sum()
	// need to check XOR, api.XOR bug exists
	cCheck := Xor(api, proof.C1, proof.C2, 256)
	IsVariableEqual(api, proof.IsEnabled, c, cCheck)
	//cCheck := api.Xor(proof.C1, proof.C2)
	//IsVariableEqual(api, proof.IsEnabled, c, cCheck)
	// verify sum proof
	lSum := tool.ScalarBaseMul(proof.Z_sum)
	rSum := tool.Add(
		proof.A_sum,
		tool.ScalarMul(
			tool.Add(CR_sum, tool.ScalarMul(h, proof.GasFee)),
			c,
		),
	)
	IsPointEqual(api, proof.IsEnabled, lSum, rSum)
	// Verify sub proofs
	for i, subProof := range proof.SubProofs {
		// Verify valid Enc
		verifyValidEnc(
			api,
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, h, subProof.CDelta.CR, subProof.A_CRDelta,
			c,
			subProof.Z_r, subProof.Z_bDelta,
			tool,
			proof.IsEnabled,
		)
		// define variables
		var (
			CPrime, CPrimeNeg ElGamalEncConstraints
		)
		// set CPrime & CPrimeNeg
		CPrime = tool.EncAdd(subProof.C, subProof.CDelta)
		CPrimeNeg = tool.NegElgamal(CPrime)
		// verify Y_1 = g^{r_i^{\star}} h^{b_i^{\Delta}}
		l1 := tool.Add(
			tool.ScalarBaseMul(subProof.Z_rstar1),
			tool.ScalarMul(h, subProof.Z_bstar1),
		)
		r1 := tool.Add(subProof.A_Y1, tool.ScalarMul(subProof.Y, proof.C1))
		IsPointEqual(api, proof.IsEnabled, l1, r1)
		// Verify ownership
		//h_z_bprime := tool.ScalarMul(h, subProof.Z_bprime)
		// Y_2 = g^{r_{i}^{\star}} h^{b_i'}
		l2 := tool.Add(
			tool.ScalarBaseMul(subProof.Z_rstar2),
			tool.ScalarMul(h, subProof.Z_bstar2),
		)
		r2 := tool.Add(
			subProof.A_Y2,
			tool.ScalarMul(subProof.Y, proof.C2),
		)
		IsPointEqual(api, proof.IsEnabled, l2, r2)
		// set common pk
		c2 = proof.C2
		pkProofs[i] = SetPkProof(subProof.Pk, subProof.A_pk, subProof.Z_sk, subProof.Z_skInv)
		tProofs[i] = SetTProof(CPrimeNeg, subProof.A_TDivCPrime, subProof.Z_bar_r, subProof.T)
		//// pk = g^{sk}
		//l4 := tool.ScalarBaseMul(subProof.Z_sk)
		//r4 := tool.Add(
		//	subProof.A_pk,
		//	tool.ScalarMul(subProof.Pk, proof.C2),
		//)
		//IsPointEqual(api, proof.IsEnabled, l4, r4)
		//// T_i = (C_R')/(C_L')^{sk^{-1}} g^{\bar{r}_i}
		//l5 := tool.Add(
		//	tool.ScalarMul(CPrimeNeg.CL, subProof.Z_skInv),
		//	tool.ScalarBaseMul(subProof.Z_bar_r),
		//)
		//r5 := tool.Add(
		//	subProof.A_TDivCPrime,
		//	tool.ScalarMul(
		//		tool.Add(subProof.T, CPrimeNeg.CR),
		//		proof.C2,
		//	),
		//)
		//IsPointEqual(api, proof.IsEnabled, l5, r5)
	}
	proof.C_fee_DeltaForGas = ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: tool.ScalarMul(h, proof.GasFee),
	}
	return c2, pkProofs, tProofs
}

/*
	verifyValidEnc verifys the encryption
	@api: the constraint system
	@pk: the public key for the encryption
	@C_LDelta,C_RDelta: parts for the encryption
	@A_C_LDelta,A_CRDelta: random commitments
	@h: the generator
	@c: the challenge
	@z_r,z_bDelta: response values for valid Enc proof
	@params: params for the curve tebn254
*/
func verifyValidEnc(
	api API,
	pk, C_LDelta, A_CLDelta, h, C_RDelta, A_CRDelta Point,
	c Variable,
	z_r, z_bDelta Variable,
	tool *EccTool,
	isEnabled Variable,
) {
	// pk^{z_r} == A_{C_L^{\Delta}} (C_L^{\Delta})^c
	var l1, r1 Point
	l1 = tool.ScalarMul(pk, z_r)
	r1 = tool.ScalarMul(C_LDelta, c)
	r1 = tool.Add(A_CLDelta, r1)
	IsPointEqual(api, isEnabled, l1, r1)

	// g^{z_r} h^{z_b^{\Delta}} == A_{C_R^{\Delta}} (C_R^{\Delta})^c
	var gzr, l2, r2 Point
	gzr = tool.ScalarBaseMul(z_r)
	l2 = tool.ScalarMul(h, z_bDelta)
	l2 = tool.Add(gzr, l2)
	r2 = tool.ScalarMul(C_RDelta, c)
	r2 = tool.Add(A_CRDelta, r2)
	IsPointEqual(api, isEnabled, l2, r2)
}

func SetEmptyTransferProofWitness() (witness TransferProofConstraints) {
	// A_sum
	witness.A_sum, _ = SetPointWitness(BasePoint)
	// z_tsk
	witness.Z_sum = ZeroInt
	// C = C1 \oplus C2
	witness.C1 = ZeroInt
	witness.C2 = ZeroInt
	// set fee
	witness.GasFee = ZeroInt
	// set sub proofs
	for i := 0; i < NbTransferCount; i++ {
		// define var
		var subProofWitness TransferSubProofConstraints
		// set values
		// A_{C_L^{\Delta}}
		subProofWitness.A_CLDelta, _ = SetPointWitness(BasePoint)
		// A_{C_R^{\Delta}}
		subProofWitness.A_CRDelta, _ = SetPointWitness(BasePoint)
		subProofWitness.A_Y1, _ = SetPointWitness(BasePoint)

		subProofWitness.A_Y2, _ = SetPointWitness(BasePoint)

		// A_T
		subProofWitness.A_T, _ = SetPointWitness(BasePoint)

		// A_{pk}
		subProofWitness.A_pk, _ = SetPointWitness(BasePoint)

		// A_{T/C'}
		subProofWitness.A_TDivCPrime, _ = SetPointWitness(BasePoint)

		// Z_r
		subProofWitness.Z_r = ZeroInt
		// z_{b^{\Delta}}
		subProofWitness.Z_bDelta = ZeroInt
		// z_{r^{\star} - r}
		subProofWitness.Z_rstar1 = ZeroInt
		subProofWitness.Z_rstar2 = ZeroInt
		subProofWitness.Z_bstar1 = ZeroInt
		subProofWitness.Z_bstar2 = ZeroInt
		// z_{\bar{r}}
		subProofWitness.Z_bar_r = ZeroInt
		// z_{b'}
		subProofWitness.Z_bprime = ZeroInt
		// z_{sk}
		subProofWitness.Z_sk = ZeroInt
		// z_{sk}
		subProofWitness.Z_skInv = ZeroInt
		// range proof
		//subProofWitness.BStarRangeProof, err = SetCtRangeProofWitness(subProof.BStarRangeProof, isEnabled)
		//if err != nil {
		//	return witness, err
		//}
		// C
		subProofWitness.C, _ = SetElGamalEncWitness(ZeroElgamalEnc)

		// C^{\Delta}
		subProofWitness.CDelta, _ = SetElGamalEncWitness(ZeroElgamalEnc)

		// T
		subProofWitness.T, _ = SetPointWitness(BasePoint)

		// Y
		subProofWitness.Y, _ = SetPointWitness(BasePoint)

		// Pk
		subProofWitness.Pk, _ = SetPointWitness(BasePoint)

		// set into witness
		witness.SubProofs[i] = subProofWitness
	}
	witness.AssetId = ZeroInt
	witness.C_fee_DeltaForGas, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

/*
	SetTransferProofWitness set witness for the privacy transfer proof
*/
func SetTransferProofWitness(proof *zecrey.TransferProof, isEnabled bool) (witness TransferProofConstraints, err error) {
	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetTransferProofWitness] err info:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetTransferProofWitness] invalid proof")
		return witness, errors.New("[SetTransferProofWitness] invalid proof")
	}
	// A_sum
	witness.A_sum, err = SetPointWitness(proof.A_sum)
	if err != nil {
		return witness, err
	}
	// z_tsk
	witness.Z_sum = proof.Z_sum
	if err != nil {
		return witness, err
	}
	// C = C1 \oplus C2
	witness.C1 = proof.C1
	witness.C2 = proof.C2
	// set fee
	witness.GasFee = proof.GasFee
	// set sub proofs
	for i, subProof := range proof.SubProofs {
		// set into witness
		witness.SubProofs[i], err = SetTransferSubProofWitness(subProof)
		if err != nil {
			return witness, err
		}
	}
	witness.AssetId = uint64(proof.AssetId)
	witness.C_fee_DeltaForGas, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

func SetTransferSubProofWitness(subProof *zecrey.TransferSubProof) (
	subProofWitness TransferSubProofConstraints,
	err error,
) {
	// set values
	// A_{C_L^{\Delta}}
	subProofWitness.A_CLDelta, err = SetPointWitness(subProof.A_CLDelta)
	if err != nil {
		return subProofWitness, err
	}
	// A_{C_R^{\Delta}}
	subProofWitness.A_CRDelta, err = SetPointWitness(subProof.A_CRDelta)
	if err != nil {
		return subProofWitness, err
	}
	subProofWitness.A_Y1, err = SetPointWitness(subProof.A_Y1)
	if err != nil {
		return subProofWitness, err
	}
	subProofWitness.A_Y2, err = SetPointWitness(subProof.A_Y2)
	if err != nil {
		return subProofWitness, err
	}
	// A_T
	subProofWitness.A_T, err = SetPointWitness(subProof.A_T)
	if err != nil {
		return subProofWitness, err
	}
	// A_{pk}
	subProofWitness.A_pk, err = SetPointWitness(subProof.A_pk)
	if err != nil {
		return subProofWitness, err
	}
	// A_{T/C'}
	subProofWitness.A_TDivCPrime, err = SetPointWitness(subProof.A_TDivCPrime)
	if err != nil {
		return subProofWitness, err
	}
	// Z_r
	subProofWitness.Z_r = subProof.Z_r
	// z_{b^{\Delta}}
	subProofWitness.Z_bDelta = subProof.Z_bDelta
	// z_{r^{\star} - r}
	subProofWitness.Z_rstar1 = subProof.Z_rstar1
	subProofWitness.Z_rstar2 = subProof.Z_rstar2
	subProofWitness.Z_bstar1 = subProof.Z_bstar1
	subProofWitness.Z_bstar2 = subProof.Z_bstar2
	// z_{\bar{r}}
	subProofWitness.Z_bar_r = subProof.Z_rbar
	// z_{b'}
	subProofWitness.Z_bprime = subProof.Z_bprime
	// z_{sk}
	subProofWitness.Z_sk = subProof.Z_sk
	// z_{sk}
	subProofWitness.Z_skInv = subProof.Z_skInv
	// range proof
	//subProofWitness.BStarRangeProof, err = SetCtRangeProofWitness(subProof.BStarRangeProof, isEnabled)
	//if err != nil {
	//	return witness, err
	//}
	// C
	subProofWitness.C, err = SetElGamalEncWitness(subProof.C)
	if err != nil {
		return subProofWitness, err
	}
	// C^{\Delta}
	subProofWitness.CDelta, err = SetElGamalEncWitness(subProof.CDelta)
	if err != nil {
		return subProofWitness, err
	}
	// T
	subProofWitness.T, err = SetPointWitness(subProof.T)
	if err != nil {
		return subProofWitness, err
	}
	// Y
	subProofWitness.Y, err = SetPointWitness(subProof.Y)
	if err != nil {
		return subProofWitness, err
	}
	// Pk
	subProofWitness.Pk, err = SetPointWitness(subProof.Pk)
	if err != nil {
		return subProofWitness, err
	}
	return subProofWitness, nil
}
