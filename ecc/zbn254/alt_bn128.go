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

package zbn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
	"github.com/bnb-chain/zkbas-crypto/util"
)

var (
	Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	SeedH    = "ZecreyBN128SetupH"
)

type G1Affine = bn254.G1Affine

func HashToG1(m string) (*G1Affine, error) {
	p, err := bn254.HashToCurveG1Svdw([]byte(m), []byte(m))
	return &p, err
}

func GetG1InfinityPoint() *G1Affine {
	p := new(G1Affine)
	p.X.SetZero()
	p.Y.SetZero()
	return p
}

func G1Add(a, b *G1Affine) *G1Affine {
	aJac := new(bn254.G1Jac).FromAffine(a)
	p := new(G1Affine).FromJacobian(aJac.AddMixed(b))
	return p
}

func G1ScalarMul(a *G1Affine, s *big.Int) *G1Affine {
	return new(G1Affine).ScalarMultiplication(a, s)
}

func G1ScalarHBaseMul(s *big.Int) *G1Affine {
	_, HAffine := GetG1TwoBaseAffine()
	return new(G1Affine).ScalarMultiplication(HAffine, s)
}

func G1ScalarBaseMul(s *big.Int) *G1Affine {
	base := G1BaseAffine()
	return new(G1Affine).ScalarMultiplication(base, s)
}

func G1BaseAffine() (*G1Affine) {
	_, _, G1Affine, _ := bn254.Generators()
	return &G1Affine
}

func GetG1TwoBaseAffine() (g *G1Affine, h *G1Affine) {
	_, _, G1Affine, _ := bn254.Generators()
	HAffine, _ := HashToG1(SeedH)
	return &G1Affine, HAffine
}

func G1Neg(s *G1Affine) *G1Affine {
	return new(G1Affine).Neg(s)
}

func ToBytes(a *G1Affine) []byte {
	aBytes := a.Bytes()
	return aBytes[:]
}

func VecToBytes(arr []*G1Affine) []byte {
	var res []byte
	for _, value := range arr {
		res = util.ContactBytes(res, ToBytes(value))
	}
	return res
}

func RandomValue() *big.Int {
	r, _ := ffmath.RandomValue(Order)
	return r
}
