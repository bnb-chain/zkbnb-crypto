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
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

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
