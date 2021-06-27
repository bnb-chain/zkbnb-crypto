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
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

func ProveSwapPart1(relation *SwapProofRelationPart, isFrom bool) (proof *SwapProofPart, err error) {
	if relation == nil {
		return nil, ErrInvalidParams
	}
	var (
		buf   bytes.Buffer
		CStar *ElGamalEnc
		bStar *big.Int
	)
	// check if the encryption is valid
	if isFrom {
		bStar = relation.BStarFrom
	} else {
		bStar = relation.BStarTo
	}
	CStar = relation.CStar
	CLStarCheck := curve.ScalarMul(relation.Pk, relation.RStar)
	CRStarCheck := curve.Add(curve.ScalarMul(relation.G, relation.RStar), curve.ScalarMul(relation.H, new(big.Int).Neg(bStar)))
	if !CStar.CL.Equal(CLStarCheck) || !CStar.CR.Equal(CRStarCheck) {
		return nil, ErrInvalidEncryption
	}
	// commit balance proof
	alpha_rbar, alpha_sk, alpha_skInv,
	A_pk, A_TDivCRprime := commitBalance(relation.G, relation.CLprimeInv)
	// set buf
	buf.Write(relation.G.Marshal())
	buf.Write(relation.H.Marshal())
	buf.Write(relation.Ht1.Marshal())
	buf.Write(relation.Ht2.Marshal())
	buf.Write(relation.C.CL.Marshal())
	buf.Write(relation.C.CR.Marshal())
	buf.Write(relation.CStar.CL.Marshal())
	buf.Write(relation.CStar.CR.Marshal())
	buf.Write(relation.T.Marshal())
	buf.Write(relation.Pk.Marshal())
	buf.Write(relation.BStarFrom.Bytes())
	buf.Write(relation.BStarTo.Bytes())
	buf.Write(A_pk.Marshal())
	buf.Write(A_TDivCRprime.Marshal())
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	A_Pt1, _ := provePt(alpha_sk, relation.Sk, relation.Ht1, c)
	A_Pt2, _ := provePt(alpha_sk, relation.Sk, relation.Ht2, c)
	//z_r := respondHalfEnc(relation.RStar, alpha_r, c)
	z_rbar, z_sk, z_skInv := respondBalance(relation.RBar, relation.Sk, alpha_rbar, alpha_sk, alpha_skInv, c)
	// range proof
	// make range proofs
	rangeProof, err := commitRange.Prove(relation.BPrime, relation.RBar, relation.T, H, G, N)
	if err != nil {
		return nil, err
	}
	proof = &SwapProofPart{
		// commitments
		Pt1:           relation.Pt1,
		Pt2:           relation.Pt2,
		A_pk:          A_pk,
		A_TDivCRprime: A_TDivCRprime,
		A_Pt1:         A_Pt1,
		A_Pt2:         A_Pt2,
		// response
		Z_rbar:  z_rbar,
		Z_sk:    z_sk,
		Z_skInv: z_skInv,
		// Commitment Range Proofs
		RangeProof: rangeProof,
		// common inputs
		BStar1:      relation.BStarFrom,
		BStar2:      relation.BStarTo,
		RStar:       relation.RStar,
		CStar:       relation.CStar,
		C:           relation.C,
		G:           relation.G,
		H:           relation.H,
		Ht1:         relation.Ht1,
		Ht2:         relation.Ht2,
		TDivCRprime: relation.TDivCRprime,
		CLprimeInv:  relation.CLprimeInv,
		T:           relation.T,
		Pk:          relation.Pk,
		Challenge:   c,
	}
	return proof, nil
}

func ProveSwapPart2(relation *SwapProofRelationPart, proofPart1 *SwapProofPart) (proof *SwapProof, err error) {
	if relation == nil || proofPart1 == nil || !relation.Ht1.Equal(proofPart1.Ht1) || !relation.Ht2.Equal(proofPart1.Ht2) || !ffmath.Equal(relation.BStarFrom, proofPart1.BStar1) || !ffmath.Equal(relation.BStarTo, proofPart1.BStar2) {
		return nil, ErrInvalidParams
	}
	// Verify the proof part first
	partRes, err := proofPart1.Verify()
	if err != nil || !partRes {
		return nil, ErrInvalidSwapProof
	}
	proofPart2, err := ProveSwapPart1(relation, false)
	if err != nil {
		return nil, err
	}
	proof = &SwapProof{
		ProofPart1: proofPart1,
		ProofPart2: proofPart2,
	}
	return proof, nil
}

func (proof *SwapProofPart) Verify() (bool, error) {
	if proof == nil {
		return false, ErrInvalidParams
	}
	if proof.BStar1.Cmp(Zero) <= 0 || proof.BStar2.Cmp(Zero) <= 0 {
		return false, ErrInvalidBStar
	}
	// Verify range proof first
	rangeRes, err := proof.RangeProof.Verify()
	if err != nil || !rangeRes {
		return false, err
	}
	// generate the challenge
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht1.Marshal())
	buf.Write(proof.Ht2.Marshal())
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
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// Verify challenge
	if !ffmath.Equal(c, proof.Challenge) {
		return false, ErrInvalidChallenge
	}
	// Verify Ht
	ptRes1, err := verifyPt(proof.Ht1, proof.Pt1, proof.A_Pt1, c, proof.Z_sk)
	if err != nil || !ptRes1 {
		return false, err
	}
	ptRes2, err := verifyPt(proof.Ht2, proof.Pt2, proof.A_Pt2, c, proof.Z_sk)
	if err != nil || !ptRes2 {
		return false, err
	}
	// Verify balance
	balanceRes, err := verifyBalance(proof.G, proof.Pk, proof.A_pk, proof.CLprimeInv, proof.TDivCRprime, proof.A_TDivCRprime, c, proof.Z_sk, proof.Z_skInv, proof.Z_rbar)
	if err != nil {
		return false, err
	}
	return balanceRes, nil
}

func (proof *SwapProof) Verify() (bool, error) {
	if proof == nil {
		return false, ErrInvalidParams
	}
	// Verify part 1
	part1Res, err := proof.ProofPart1.Verify()
	if err != nil || !part1Res {
		return false, err
	}
	// Verify part2
	part2Res, err := proof.ProofPart2.Verify()
	if err != nil || !part2Res {
		return false, err
	}
	return true, nil
}
