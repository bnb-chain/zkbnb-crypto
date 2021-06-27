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
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

func ProveWithdraw(relation *WithdrawProofRelation) (proof *WithdrawProof, err error) {
	if relation == nil {
		return nil, ErrInvalidParams
	}
	alpha_rbar, alpha_sk, alpha_skInv,
	A_pk, A_TDivCRprime := commitBalance(relation.G, relation.CLprimeInv)
	// write common inputs into buf
	// then generate the challenge c
	var buf bytes.Buffer
	buf.Write(relation.G.Marshal())
	buf.Write(relation.H.Marshal())
	buf.Write(relation.Ht.Marshal())
	buf.Write(relation.Pt.Marshal())
	buf.Write(relation.Ha.Marshal())
	buf.Write(relation.Pa.Marshal())
	buf.Write(relation.C.CL.Marshal())
	buf.Write(relation.C.CR.Marshal())
	buf.Write(relation.CRStar.Marshal())
	buf.Write(relation.T.Marshal())
	buf.Write(relation.Pk.Marshal())
	buf.Write(A_pk.Marshal())
	buf.Write(A_TDivCRprime.Marshal())
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	//z_r := respondHalfEnc(relation.RStar, alpha_r, c)
	z_rbar, z_sk, z_skInv := respondBalance(relation.RBar, relation.Sk, alpha_rbar, alpha_sk, alpha_skInv, c)
	A_Pt, _ := provePt(alpha_sk, relation.Sk, relation.Ht, c)
	A_Pa, _ := provePt(alpha_sk, relation.Sk, relation.Ha, c)
	// range proof
	// make range proofs
	rangeProof, err := commitRange.Prove(relation.BPrime, relation.RBar, relation.T, H, G, N)
	if err != nil {
		return nil, err
	}

	proof = &WithdrawProof{
		// commitments
		A_pk:          A_pk,
		A_TDivCRprime: A_TDivCRprime,
		A_Pt:          A_Pt,
		A_Pa:          A_Pa,
		// response
		Z_rbar:  z_rbar,
		Z_sk:    z_sk,
		Z_skInv: z_skInv,
		// BP Proof
		CRangeProof: rangeProof,
		// common inputs
		BStar:       relation.Bstar,
		G:           relation.G,
		H:           relation.H,
		Ht:          relation.Ht,
		Pt:          relation.Pt,
		Ha:          relation.Ha,
		Pa:          relation.Pa,
		TDivCRprime: relation.TDivCRprime,
		CLprimeInv:  relation.CLprimeInv,
		C:           relation.C,
		CRStar:      relation.CRStar,
		T:           relation.T,
		Pk:          relation.Pk,
		Challenge:   c,
	}
	return proof, nil
}

func (proof *WithdrawProof) Verify() (bool, error) {
	if proof.BStar.Cmp(Zero) >= 0 {
		return false, ErrInvalidBStar
	}
	// Verify range proof first
	rangeRes, err := proof.CRangeProof.Verify()
	if err != nil || !rangeRes {
		return false, err
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
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// Verify challenge
	if !ffmath.Equal(c, proof.Challenge) {
		return false, ErrInvalidChallenge
	}
	// Verify Ht
	ptRes, err := verifyPt(proof.Ht, proof.Pt, proof.A_Pt, c, proof.Z_sk)
	if err != nil || !ptRes {
		return false, err
	}
	paRes, err := verifyPt(proof.Ha, proof.Pa, proof.A_Pa, c, proof.Z_sk)
	if err != nil || !paRes {
		return false, err
	}
	// Verify balance
	balanceRes, err := verifyBalance(proof.G, proof.Pk, proof.A_pk, proof.CLprimeInv, proof.TDivCRprime, proof.A_TDivCRprime, c, proof.Z_sk, proof.Z_skInv, proof.Z_rbar)
	if err != nil {
		return false, err
	}
	return balanceRes, nil
}

func commitBalance(g, CLprimeInv *Point) (
	alpha_rbar, alpha_sk, alpha_skInv *big.Int,
	A_pk, A_TDivCRprime *Point,
) {
	alpha_rbar = curve.RandomValue()
	alpha_sk = curve.RandomValue()
	alpha_skInv = ffmath.ModInverse(alpha_sk, Order)
	A_pk = curve.ScalarMul(g, alpha_sk)
	A_TDivCRprime = curve.Add(curve.ScalarMul(g, alpha_rbar), curve.ScalarMul(CLprimeInv, alpha_skInv))
	return
}

func respondBalance(
	rbar, sk, alpha_rbar, alpha_sk, alpha_skInv, c *big.Int,
) (
	z_rbar, z_sk, z_skInv *big.Int,
) {
	z_rbar = ffmath.AddMod(alpha_rbar, ffmath.Multiply(c, rbar), Order)
	z_sk = ffmath.AddMod(alpha_sk, ffmath.Multiply(c, sk), Order)
	skInv := ffmath.ModInverse(sk, Order)
	z_skInv = ffmath.AddMod(alpha_skInv, ffmath.Multiply(c, skInv), Order)
	return
}

func verifyBalance(
	g, pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime *Point,
	c *big.Int,
	z_sk, z_skInv, z_rbar *big.Int,
) (bool, error) {
	if g == nil || pk == nil || A_pk == nil || CLprimeInv == nil || TDivCRprime == nil || A_TDivCRprime == nil || c == nil ||
		z_sk == nil || z_skInv == nil || z_rbar == nil {
		return false, ErrInvalidParams
	}
	// Verify pk = g^{sk}
	l1 := curve.ScalarMul(g, z_sk)
	r1 := curve.Add(A_pk, curve.ScalarMul(pk, c))
	if !l1.Equal(r1) {
		return false, nil
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l2 := curve.Add(curve.ScalarMul(g, z_rbar), curve.ScalarMul(CLprimeInv, z_skInv))
	r2 := curve.Add(A_TDivCRprime, curve.ScalarMul(TDivCRprime, c))
	return l2.Equal(r2), nil
}

func TryOnceWithdraw() WithdrawProof {
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, _ := twistedElgamal.Enc(b, r, pk)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	bStar := big.NewInt(-2)
	relation, _ := NewWithdrawRelation(bEnc, pk, bStar, sk, 1, "0x99AC8881834797ebC32f185ee27c2e96842e1a47")
	withdrawProof, _ := ProveWithdraw(relation)
	return *withdrawProof
}
