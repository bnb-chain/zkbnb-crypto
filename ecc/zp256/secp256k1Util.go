package zp256

import (
	"PrivaL-crypto/ffmath"
	"PrivaL-crypto/util"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
)

const (
	SeedH = "ZKSneakP256HSeed"
	SeedU = "ZKSnekP256USeed"
)

func Neg(a *P256) *P256 {
	return new(P256).Neg(a)
}

func Add(a, b *P256) *P256 {
	return new(P256).Multiply(a, b)
}

func ScalarBaseMult(a *big.Int) *P256 {
	return new(P256).ScalarBaseMult(a)
}

func ScalarHBaseMult(a *big.Int) *P256 {
	return new(P256).ScalarMult(H, a)
}

func ScalarMult(a *P256, n *big.Int) *P256 {
	return new(P256).ScalarMult(a, n)
}

func Set(a *P256) *P256 {
	res := &P256{}
	res.X.Set(a.X)
	res.Y.Set(a.Y)
	return res
}

func Base() *P256 {
	return &P256{X: Curve.Gx, Y: Curve.Gy}
}

func VecToBytes(a []*P256) []byte {
	aBytes, _ := json.Marshal(a)
	return aBytes
}

func Equal(a, b *P256) bool {
	return a.String() == b.String()
}

func InfinityPoint() *P256 {
	res := &P256{}
	res.SetInfinity()
	return res
}

func RandomValue() *big.Int {
	return ffmath.RandomValue(Curve.N)
}

/*
MapToGroup is a hash function that returns a valid elliptic curve point given as
input a string. It is also known as hash-to-point and is used to obtain a generator
that has no discrete logarithm known relation, thus addressing the concept of
NUMS (nothing up my sleeve).
This implementation is based on the paper:
Short signatures from the Weil pairing
Boneh, Lynn and Shacham
Journal of Cryptology, September 2004, Volume 17, Issue 4, pp 297–319
*/
func MapToGroup(m string) (*P256, error) {
	var (
		i      int
		buffer bytes.Buffer
	)
	i = 0
	for i < 256 {
		buffer.Reset()
		buffer.WriteString(strconv.Itoa(i))
		buffer.WriteString(m)
		x, _ := util.HashToInt(buffer, sha256.New)
		x = ffmath.Mod(x, Curve.P)
		fx, _ := F(x)
		fx = ffmath.Mod(fx, Curve.P)
		y := fx.ModSqrt(fx, Curve.P)
		if y != nil {
			p := &P256{X: x, Y: y}
			if p.IsOnCurve() && !p.IsZero() {
				return p, nil
			}
		}
		i = i + 1
	}
	return nil, errors.New("Failed to Hash-to-point.")
}

/*
F receives a big integer x as input and return x^3 + 7 mod ORDER.
*/
func F(x *big.Int) (*big.Int, error) {
	// Compute x^2
	x3p7 := ffmath.Multiply(x, x)
	x3p7 = ffmath.Mod(x3p7, Curve.P)
	// Compute x^3
	x3p7 = ffmath.Multiply(x3p7, x)
	x3p7 = ffmath.Mod(x3p7, Curve.P)
	// Compute X^3 + 7
	x3p7 = ffmath.Add(x3p7, new(big.Int).SetInt64(7))
	x3p7 = ffmath.Mod(x3p7, Curve.P)
	return x3p7, nil
}
