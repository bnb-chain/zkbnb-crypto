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
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func ProveWithdraw(relation *WithdrawProofRelation) (proof *WithdrawProof, err error) {
	if relation == nil {
		log.Println("[ProveWithdraw] invalid params")
		return nil, ErrInvalidParams
	}
	var (
		alpha_rbar, alpha_sk, alpha_skInv *big.Int
		A_pk, A_TDivCRprime               *Point
		A_Pa                              *Point
		CLPrimeInv                        *Point
		buf                               bytes.Buffer
	)
	CLPrimeInv = curve.Neg(relation.C.CL)
	alpha_rbar, alpha_sk, alpha_skInv,
		A_pk, A_TDivCRprime = commitBalance(relation.G, CLPrimeInv)
	A_Pa = curve.ScalarMul(relation.Ha, alpha_sk)
	// write common inputs into buf
	// then generate the challenge c
	writePointIntoBuf(&buf, relation.G)
	writePointIntoBuf(&buf, relation.H)
	writePointIntoBuf(&buf, relation.Ha)
	writePointIntoBuf(&buf, relation.Pa)
	writeEncIntoBuf(&buf, relation.C)
	writePointIntoBuf(&buf, relation.CRStar)
	writePointIntoBuf(&buf, relation.T)
	writePointIntoBuf(&buf, relation.Pk)
	writePointIntoBuf(&buf, A_pk)
	writePointIntoBuf(&buf, A_TDivCRprime)
	writePointIntoBuf(&buf, A_Pa)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	z_rbar, z_sk, z_skInv := respondBalance(relation.RBar, relation.Sk, alpha_rbar, alpha_sk, alpha_skInv, c)
	proof = &WithdrawProof{
		// commitments
		A_pk:          A_pk,
		A_TDivCRprime: A_TDivCRprime,
		A_Pa:          A_Pa,
		// response
		Z_rbar:  z_rbar,
		Z_sk:    z_sk,
		Z_skInv: z_skInv,
		// BP Proof
		BPrimeRangeProof: relation.BPrimeRangeProof,
		// common inputs
		BStar:       relation.Bstar,
		Fee:         relation.Fee,
		G:           relation.G,
		H:           relation.H,
		Ha:          relation.Ha,
		Pa:          relation.Pa,
		C:           relation.C,
		CRStar:      relation.CRStar,
		T:           relation.T,
		Pk:          relation.Pk,
		ReceiveAddr: relation.ReceiveAddr,
	}
	return proof, nil
}

func (proof *WithdrawProof) Verify() (bool, error) {
	if !validUint64(proof.BStar) || !validUint64(proof.Fee) {
		log.Println("[Verify WithdrawProof] invalid params")
		return false, errors.New("[Verify WithdrawProof] invalid params")
	}
	// check Ha
	HaCheck := curve.ScalarMul(proof.H, proof.ReceiveAddr)
	if !proof.Ha.Equal(HaCheck) {
		log.Println("[Verify WithdrawProof] invalid params")
		return false, ErrInvalidParams
	}
	// verify if the CRStar is correct
	hNeg := curve.Neg(proof.H)
	CRCheck := curve.ScalarMul(hNeg, big.NewInt(int64(proof.BStar+proof.Fee)))
	if !proof.CRStar.Equal(CRCheck) {
		log.Println("[Verify WithdrawProof] invalid params")
		return false, ErrInvalidParams
	}
	// Verify range proof first
	rangeRes, err := proof.BPrimeRangeProof.Verify()
	if err != nil {
		log.Println("[Verify WithdrawProof] err info:", err)
		return false, err
	}
	if !rangeRes {
		log.Println("[Verify WithdrawProof] invalid range proof")
		return false, errors.New("[Verify WithdrawProof] invalid range proof")
	}
	// generate the challenge
	var (
		CLprimeInv, TDivCRprime *Point
		buf                     bytes.Buffer
	)
	CLprimeInv = curve.Neg(proof.C.CL)
	TDivCRprime = curve.Add(proof.T, curve.Neg(curve.Add(proof.C.CR, proof.CRStar)))
	writePointIntoBuf(&buf, proof.G)
	writePointIntoBuf(&buf, proof.H)
	writePointIntoBuf(&buf, proof.Ha)
	writePointIntoBuf(&buf, proof.Pa)
	writeEncIntoBuf(&buf, proof.C)
	writePointIntoBuf(&buf, proof.CRStar)
	writePointIntoBuf(&buf, proof.T)
	writePointIntoBuf(&buf, proof.Pk)
	writePointIntoBuf(&buf, proof.A_pk)
	writePointIntoBuf(&buf, proof.A_TDivCRprime)
	writePointIntoBuf(&buf, proof.A_Pa)
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		log.Println("[Verify WithdrawProof] err: unable to compute hash:", err)
		return false, err
	}
	// Verify Pa
	l1 := curve.ScalarMul(proof.Ha, proof.Z_sk)
	r1 := curve.Add(proof.A_Pa, curve.ScalarMul(proof.Pa, c))
	if !l1.Equal(r1) {
		log.Println("[Verify WithdrawProof] l1 != r1")
		return false, nil
	}
	// Verify balance
	balanceRes, err := verifyBalance(proof.G, proof.Pk, proof.A_pk, CLprimeInv, TDivCRprime, proof.A_TDivCRprime, c, proof.Z_sk, proof.Z_skInv, proof.Z_rbar)
	if err != nil {
		log.Println("err info:", err)
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

/*
	verifyBalance: verify if the owner balance is correct
*/
func verifyBalance(
	g, pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime *Point,
	c *big.Int,
	z_sk, z_skInv, z_rbar *big.Int,
) (bool, error) {
	// Verify pk = g^{sk}
	l1 := curve.ScalarMul(g, z_sk)
	r1 := curve.Add(A_pk, curve.ScalarMul(pk, c))
	if !l1.Equal(r1) {
		log.Println("[verifyBalance] l1!=r1")
		return false, nil
	}
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	l2 := curve.Add(curve.ScalarMul(g, z_rbar), curve.ScalarMul(CLprimeInv, z_skInv))
	r2 := curve.Add(A_TDivCRprime, curve.ScalarMul(TDivCRprime, c))
	if !l2.Equal(r2) {
		log.Println("[verifyBalance] l2!=r2")
		return false, nil
	}
	return true, nil
}
