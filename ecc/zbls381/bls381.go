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

package zbls381

import (
	"github.com/bnb-chain/zkbnb-crypto/ffmath"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/big"
)

var (
	Order, _ = new(big.Int).SetString("8444461749428370424248824938781546531375899335154063827935233455917409239041", 10)
	SEEDH    = "ZecreyBLS377SetupH"
)

type G1Affine = bls12381.G1Affine

func G1Base() *G1Affine {
	_, _, g1Aff, _ := bls12381.Generators()
	return &g1Aff
}

func G1ScalarMul(a *G1Affine, b *big.Int) *G1Affine {
	return new(G1Affine).ScalarMultiplication(a, b)
}

func G1ScalarBaseMul(a *big.Int) *G1Affine {
	return new(G1Affine).ScalarMultiplication(G1Base(), a)
}

func G1Add(a, b *G1Affine) *G1Affine {
	aJac := new(bls12381.G1Jac).FromAffine(a)
	p := new(G1Affine).FromJacobian(aJac.AddMixed(b))
	return p
}

func G1Neg(a *G1Affine) *G1Affine {
	return new(G1Affine).Neg(a)
}

func G1InfinityPoint() *G1Affine {
	p := &G1Affine{}
	p.X.SetZero()
	p.Y.SetZero()
	return p
}

func HashToG1(m string) (*G1Affine, error) {
	p, err := bls12381.HashToCurveG1Svdw([]byte(m), []byte(m))
	return &p, err
}

func G1ScalarHBaseMul(a *big.Int) *G1Affine {
	_, h := GetG1TwoBaseAffine()
	return new(G1Affine).ScalarMultiplication(h, a)
}

func GetG1TwoBaseAffine() (g *G1Affine, h *G1Affine) {
	_, _, G1Affine, _ := bls12381.Generators()
	HAffine, _ := HashToG1(SEEDH)
	return &G1Affine, HAffine
}

func RandomValue() *big.Int {
	r, _ := ffmath.RandomValue(Order)
	return r
}
