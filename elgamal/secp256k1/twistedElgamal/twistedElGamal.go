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

package twistedElgamal

import (
	"math/big"
	"zecrey-crypto/commitment/secp256k1/pedersen"
	curve "zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
)

var (
	Order = curve.Curve.N
	G     = curve.Base()
	H     = curve.H
)

type Point = curve.P256

type ElGamalEnc struct {
	CL *Point // pk^r
	CR *Point // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := curve.Add(C1.CL, C2.CL)
	CR := curve.Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.ScalarBaseMul(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = curve.Set(enc.CL)
	value.CR = curve.Set(enc.CR)
}

func Pk(sk *big.Int) (pk *Point) {
	pk = curve.ScalarBaseMul(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc) {
	// pk^r
	CL := curve.ScalarMul(pk, r)
	// g^r h^b
	CR := pedersen.Commit(r, b, G, H)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.ScalarMul(enc.CL, skInv)
	hExpb := curve.Add(enc.CR, curve.Neg(gExpr))
	for i := int64(0); i < Max; i++ {
		b := big.NewInt(int64(i))
		hi := curve.ScalarMul(H, b)
		if curve.Equal(hi, hExpb) {
			return b
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int64, Max int64) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.ScalarMul(enc.CL, skInv)
	hExpb := curve.Add(enc.CR, curve.Neg(gExpr))
	for i := int64(start); i < Max; i++ {
		b := big.NewInt(int64(i))
		hi := curve.ScalarMul(H, b)
		if curve.Equal(hi, hExpb) {
			return b
		}
	}
	return nil
}
