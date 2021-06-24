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

package tebn254

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
	"strconv"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

var (
	curve = twistededwards.GetEdwardsCurve()
	Order = &curve.Order
	G     = &curve.Base
	H     *Point
	U     *Point
	O     = Point{X: *new(fr.Element).SetZero(), Y: *new(fr.Element).SetOne()}
)

const (
	SeedH = "ZecreyTwistedEdwardsBn254HSeed"
	SeedU = "ZecreyTwistedEdwardsBn254USeed"
)

type Point = twistededwards.PointAffine

func Add(a, b *Point) *Point {
	return new(Point).Add(a, b)
}

func ScalarBaseMul(a *big.Int) *Point {
	return new(Point).ScalarMul(G, a)
}

func ScalarMul(p *Point, a *big.Int) *Point {
	return new(Point).ScalarMul(p, a)
}

func Neg(a *Point) *Point {
	return new(Point).Neg(a)
}

func ToBytes(p *Point) []byte {
	return p.Marshal()
}

func ToString(p *Point) string {
	return hex.EncodeToString(p.Marshal())
}

func FromString(pStr string) (*Point, error) {
	pBytes, err := hex.DecodeString(pStr)
	if err != nil {
		return nil, err
	}
	return FromBytes(pBytes)
}

func FromBytes(pBytes []byte) (*Point, error) {
	var p Point
	_, err := p.SetBytes(pBytes)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func IsInSubGroup(p *Point) bool {
	if !p.IsOnCurve() {
		return false
	}
	res := new(Point).ScalarMul(p, Order)
	return IsZero(res)
}

func MapToGroup(seed string) (H *Point, err error) {
	var (
		i      int
		buffer bytes.Buffer
	)
	i = 0
	for i < 256 {
		buffer.Reset()
		buffer.WriteString(seed)
		buffer.WriteString(strconv.Itoa(i))
		y, err := util.HashToInt(buffer, zmimc.Hmimc)
		if err != nil {
			return nil, err
		}
		y = ffmath.Mod(y, Order)
		yElement := new(fr.Element).SetBigInt(y)
		x := computeX(y)
		H = &Point{X: x, Y: *yElement}
		if IsInSubGroup(H) && !IsZero(H) {
			return H, nil
		}
		i++
	}
	return nil, ErrMapToGroup
}

func computeX(yInt *big.Int) (x fr.Element) {
	y := new(fr.Element).SetBigInt(yInt)
	var one, num, den fr.Element
	one.SetOne()
	num.Square(y)
	curve := twistededwards.GetEdwardsCurve()
	den.Mul(&num, &curve.D)
	num.Sub(&one, &num)
	den.Sub(&curve.A, &den)
	x.Div(&num, &den)
	x.Sqrt(&x)
	return
}

func IsZero(p *Point) bool {
	if p == nil {
		return true
	}
	return p.Equal(&O)
}

func ZeroPoint() *Point {
	return &Point{X: *new(fr.Element).SetZero(), Y: *new(fr.Element).SetOne()}
}

func VecToBytes(vp []*Point) ([]byte, error) {
	vpBytes, err := json.Marshal(vp)
	return vpBytes, err
}

func RandomValue() *big.Int {
	r, _ := ffmath.RandomValue(Order)
	return r
}

func init() {
	H, _ = MapToGroup(SeedH)
	U, _ = MapToGroup(SeedU)
}
