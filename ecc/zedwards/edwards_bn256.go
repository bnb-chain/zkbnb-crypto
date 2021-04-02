package zedwards

import (
	"PrivaL-crypto/ffmath"
	"PrivaL-crypto/util"
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/consensys/gurvy/bn256/twistededwards"
	"math/big"
	"strconv"
)

type Point = twistededwards.PointAffine

var Curve = twistededwards.GetEdwardsCurve()
var Base = Curve.Base
var Order = Curve.Order

func ScalarMult(a *Point, b *big.Int) *Point {
	return new(Point).ScalarMul(a, b)
}

func Add(a, b *Point) *Point {
	aJac := new(twistededwards.PointProj).FromAffine(a)
	bJac := new(twistededwards.PointProj).FromAffine(b)
	C := new(twistededwards.PointProj).Add(aJac, bJac)
	return new(Point).FromProj(C)
}

func Neg(a *Point) *Point {
	res := &Point{}
	res.X.Set(&a.X)
	res.Y.Neg(&a.Y)
	return res
}

func ScalarBaseMult(a *big.Int) *Point {
	return new(Point).ScalarMul(&Base, a)
}

func InfinityPoint() *Point {
	x := new(fr.Element).SetZero()
	y := new(fr.Element).SetZero()
	return &Point{X: *x, Y: *y}
}

func Bytes(a *Point) []byte {
	t := a.Bytes()
	return t[:]
}

func MapToGroup(m string) (p *Point, err error) {
	var (
		i   int
		buf bytes.Buffer
	)
	i = 0
	for i < 256 {
		buf.Reset()
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(m)
		yInt, _ := util.HashToInt(buf, sha256.New)
		yInt = ffmath.Mod(yInt, &Order)
		y := new(fr.Element).SetBigInt(yInt)
		x := computeX(y)
		if y != nil {
			p = &Point{X: x, Y: *y}
			if p.IsOnCurve() && !IsInfinity(p) {
				return p, nil
			}
		}
		i = i + 1
	}
	return nil, errors.New("Failed to Hash-to-point.")
}

func IsInfinity(a *Point) bool {
	return a.X.IsZero() && a.Y.IsZero()
}

// ax^2 + y^2 = 1 + d*x^2*y^2
func computeX(y *fr.Element) (x fr.Element) {
	var one, num, den fr.Element
	one.SetOne()
	num.Square(y)
	den.Mul(&num, &Curve.D)
	num.Sub(&one, &num)
	den.Sub(&Curve.A, &den)
	x.Div(&num, &den)
	x.Sqrt(&x)
	return
}

func RandomValue() *big.Int {
	return ffmath.RandomValue(&Order)
}
