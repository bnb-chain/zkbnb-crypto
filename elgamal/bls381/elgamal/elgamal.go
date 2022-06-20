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

package elgamal

import (
	"math/big"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/zbls381"
)

var ORDER = curve.Order

type Point = curve.G1Affine

type ElGamalEnc struct {
	CL *Point
	CR *Point
}

func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.G1ScalarBaseMul(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := curve.G1Add(C1.CL, C2.CL)
	CR := curve.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(Point).Set(enc.CL)
	value.CR = new(Point).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc) {
	// g^r
	CL := curve.G1ScalarBaseMul(r)
	// g^b pk^r
	CR := curve.G1ScalarBaseMul(b)
	CR = curve.G1Add(CR, curve.G1ScalarMul(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.G1Add(enc.CR, curve.G1Neg(pkExpr))
	for i := int64(0); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.G1ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.G1Add(enc.CR, curve.G1Neg(pkExpr))
	for i := int64(start); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.G1ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}
