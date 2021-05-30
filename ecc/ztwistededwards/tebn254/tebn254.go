package tebn254

import (
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
	"strconv"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/util"
)

var (
	curve = twistededwards.GetEdwardsCurve()
	Order = &curve.Order
	G     = &curve.Base
	H     *Point
	U     *Point
	O     *Point
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
	//if a.Cmp(big.NewInt(0)) < 0 {
	//	return Neg(new(Point).ScalarMul(G, a))
	//}
	return new(Point).ScalarMul(G, a)
}

func ScalarMul(p *Point, a *big.Int) *Point {
	if a.Cmp(big.NewInt(0)) < 0 {
		return Neg(new(Point).ScalarMul(p, a))
	}
	return new(Point).ScalarMul(p, a)
}

func Neg(a *Point) *Point {
	return new(Point).Set(a).Neg(a)
}

func ToBytes(p *Point) []byte {
	return p.Marshal()
}

func FromBytes(pBytes []byte) (*Point, error) {
	var p *Point
	_, err := p.SetBytes(pBytes)
	if err != nil {
		return nil, err
	}
	return p, nil
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
		y, err := util.HashToInt(buffer, sha256.New)
		if err != nil {
			return nil, err
		}
		y = ffmath.Mod(y, Order)
		yElement := new(fr.Element).SetBigInt(y)
		x := computeX(y)
		H = &Point{X: x, Y: *yElement}
		if H.IsOnCurve() && !IsInfinity(H) {
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

func IsInfinity(p *Point) bool {
	if p == nil {
		return true
	}
	return p.Equal(O)
}

func InfinityPoint() *Point {
	return O
}

func RandomValue() *big.Int {
	r, _ := ffmath.RandomValue(Order)
	return r
}

func init() {
	O = ScalarBaseMul(Order)
	H, _ = MapToGroup(SeedH)
	U, _ = MapToGroup(SeedU)
}
