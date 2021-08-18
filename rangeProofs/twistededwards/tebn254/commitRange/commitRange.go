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

package commitRange

import (
	"bytes"
	"math"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

var bitChan = make(chan int, RangeMaxBits)

/*
	prove the value in the range
	@b: the secret value
	@r: the random value
	@g,h: two generators
*/
func Prove(b *big.Int, r *big.Int, T *Point, rs [RangeMaxBits]*big.Int, g, h *Point) (proof *ComRangeProof, err error) {
	// check params
	if b == nil || b.Cmp(Zero) < 0 || r == nil || g == nil || h == nil || math.Pow(2, float64(RangeMaxBits)) < float64(b.Int64()) {
		return nil, ErrInvalidRangeParams
	}
	// check if \sum_{i=1}^32 r_i = r
	sum := big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		sum.Add(sum, rs[i])
	}
	sum.Mod(sum, Order)
	if !ffmath.Equal(sum, r) {
		return nil, ErrInvalidRangeParams
	}
	// create a new proof
	proof = new(ComRangeProof)
	proof.G = g
	proof.H = h
	proof.As = [RangeMaxBits]*Point{}
	proof.Cas, proof.Cbs = [RangeMaxBits]*Point{}, [RangeMaxBits]*Point{}
	proof.Zas, proof.Zbs = [RangeMaxBits]*big.Int{}, [RangeMaxBits]*big.Int{}
	proof.T = T
	// buf to compute the challenge
	var buf bytes.Buffer
	buf.Write(g.Marshal())
	buf.Write(h.Marshal())
	buf.Write(T.Marshal())
	// convert the value into binary
	bsInt, _ := toBinary(b, RangeMaxBits)
	// compute A_i = g^{b_i} h^{r_i}
	current := int64(1)
	for i, bi := range bsInt {
		// compute A_i
		bi2i := bi * current
		Ai, _ := pedersen.Commit(big.NewInt(bi2i), rs[i], g, h)
		buf.Write(Ai.Marshal())
		// set proof
		proof.As[i] = Ai
		current = current * 2
	}
	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	c1 := curve.RandomValue()
	c2 := ffmath.Xor(c, c1)
	base := curve.Neg(proof.G)
	proof.C1 = c1
	proof.C2 = c2
	// A2 = A1 h^{-2^i}
	var A2 *Point
	for i, bi := range bsInt {
		A2 = curve.Add(proof.As[i], base)
		go computeBitProofRoutine(rs[i], proof.As[i], A2, proof.H, c1, c2, proof, i, bi == 0)
		base.Double(base)
	}
	for i := 0; i < RangeMaxBits; i++ {
		j := <-bitChan
		if j == -1 {
			return nil, ErrInvalidRangeParams
		}
	}
	return proof, nil
}

/*
	Verify a CommitmentRangeProof
*/
func (proof *ComRangeProof) Verify() (bool, error) {
	if proof == nil {
		return false, ErrInvalidRangeParams
	}
	// reconstruct buf
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.T.Marshal())
	// set buf and
	TCheck := curve.ZeroPoint()
	for _, Ai := range proof.As {
		TCheck.Add(TCheck, Ai)
		buf.Write(Ai.Marshal())
	}
	// check commitment first
	if !TCheck.Equal(proof.T) {
		return false, ErrInvalidRangeParams
	}
	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	// check c
	cCheck := ffmath.Xor(proof.C1, proof.C2)
	if !ffmath.Equal(cCheck, c) {
		return false, ErrInvalidRangeParams
	}
	base := curve.Neg(proof.G)
	for i, A1 := range proof.As {
		A2 := curve.Add(A1, base)
		bitRes, err := verifyBitProof(proof.Zas[i], proof.Zbs[i], proof.H, proof.Cas[i], proof.Cbs[i], A1, A2, proof.C1, proof.C2)
		if err != nil || !bitRes {
			return false, err
		}
		base.Double(base)
	}
	return true, nil
}

func computeBitProofRoutine(r *big.Int, A1 *Point, A2 *Point, h *Point, c1 *big.Int, c2 *big.Int, proof *ComRangeProof, i int, isZero bool) {
	if r == nil || A1 == nil || A2 == nil || A2.Equal(A1) || h == nil || c1 == nil || c2 == nil {
		bitChan <- -1
		return
	}
	if isZero {
		a := curve.RandomValue()
		proof.Cas[i] = curve.ScalarMul(h, a)
		// za = a + c r
		proof.Zas[i] = ffmath.AddMod(a, ffmath.Multiply(c1, r), Order)
		proof.Cbs[i], proof.Zbs[i] = simBitProof(A2, h, c2)
	} else {
		proof.Cas[i], proof.Zas[i] = simBitProof(A1, h, c1)
		b := curve.RandomValue()
		proof.Cbs[i] = curve.ScalarMul(h, b)
		proof.Zbs[i] = ffmath.AddMod(b, ffmath.Multiply(c2, r), Order)
	}

	bitChan <- 1
	return
}

func simBitProof(A *Point, g *Point, cSim *big.Int) (Cs *Point, zs *big.Int) {
	zs = curve.RandomValue()
	Cs = curve.Add(
		curve.ScalarMul(g, zs),
		curve.ScalarMul(curve.Neg(A), cSim),
	)
	return Cs, zs
}

func verifyBitProof(za, zb *big.Int, h *Point, Ca, Cb *Point, A1, A2 *Point, c1, c2 *big.Int) (bool, error) {
	if za == nil || zb == nil || h == nil || Ca == nil || Cb == nil || A1 == nil || A2 == nil || c1 == nil || c2 == nil {
		return false, ErrInvalidRangeParams
	}
	// check h^{za} == Ca A1^c1
	l1 := curve.ScalarMul(h, za)
	r1 := curve.Add(Ca, curve.ScalarMul(A1, c1))
	if !l1.Equal(r1) {
		return false, nil
	}
	// check h^{zb} == Cb A2^c2
	l2 := curve.ScalarMul(h, zb)
	r2 := curve.Add(Cb, curve.ScalarMul(A2, c2))
	return l2.Equal(r2), nil
}
