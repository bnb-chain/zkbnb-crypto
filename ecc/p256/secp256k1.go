package p256

import (
	"ZKSneak/ZKSneak-crypto/ffmath"
	"ZKSneak/ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type MyBitCurve struct {
	secp256k1.BitCurve
}

// Add returns the sum of s(x1,y1) and (x2,y2)
func (BitCurve *MyBitCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	secp256k1.S256()
	z := new(big.Int).SetInt64(1)
	return BitCurve.affineFromJacobian(BitCurve.addJacobian(x1, y1, z, x2, y2, z))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (BitCurve *MyBitCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, BitCurve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, BitCurve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, BitCurve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, BitCurve.P)
	h := new(big.Int).Sub(u2, u1)
	if h.Sign() == -1 {
		h.Add(h, BitCurve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, BitCurve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, BitCurve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, BitCurve.P)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3 := new(big.Int).Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, BitCurve.P)

	y3 := new(big.Int).Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, BitCurve.P)

	z3 := new(big.Int).Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	if z3.Sign() == -1 {
		z3.Add(z3, BitCurve.P)
	}
	z3.Sub(z3, z2z2)
	if z3.Sign() == -1 {
		z3.Add(z3, BitCurve.P)
	}
	z3.Mul(z3, h)
	z3.Mod(z3, BitCurve.P)

	return x3, y3, z3
}

func (BitCurve *MyBitCurve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	zinv := new(big.Int).ModInverse(z, BitCurve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, BitCurve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, BitCurve.P)
	return
}

var theCurve = new(MyBitCurve)

func init() {
	// http://www.secg.org/sec2-v2.pdf
	theCurve.P, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	theCurve.N, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	theCurve.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
	theCurve.Gx, _ = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	theCurve.Gy, _ = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	theCurve.BitSize = 256
}

func S256() *MyBitCurve {
	return theCurve
}

var (
	CURVE = S256()
)

/*
Elliptic Curve Point struct.
*/
type P256 struct {
	X, Y *big.Int
}

/*
IsZero returns true if and only if the elliptic curve point is the point at infinity.
*/
func (p *P256) IsZero() bool {
	c1 := p.X == nil || p.Y == nil
	if !c1 {
		z := new(big.Int).SetInt64(0)
		return p.X.Cmp(z) == 0 && p.Y.Cmp(z) == 0
	}
	return true
}

/*
Neg returns the inverse of the given elliptic curve point.
*/
func (p *P256) Neg(a *P256) *P256 {
	// (X, Y) -> (X, X + Y)
	if a.IsZero() {
		return p.SetInfinity()
	}
	one := new(big.Int).SetInt64(1)
	mone := new(big.Int).Sub(CURVE.N, one)
	p.ScalarMult(p, mone)
	return p
}

/*
Input points must be distinct
*/
func (p *P256) Add(a, b *P256) *P256 {
	if a.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p
	} else if b.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p

	}
	resx, resy := CURVE.Add(a.X, a.Y, b.X, b.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
Double returns 2*P, where P is the given elliptic curve point.
*/
func (p *P256) Double(a *P256) *P256 {
	if a.IsZero() {
		return p.SetInfinity()
	}
	resx, resy := CURVE.Double(a.X, a.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
ScalarMul encapsulates the scalar Multiplication Algorithm from secP256k1.
*/
func (p *P256) ScalarMult(a *P256, n *big.Int) *P256 {
	if a.IsZero() {
		return p.SetInfinity()
	}
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = ffmath.Mod(n, CURVE.N)
	bns := n.Bytes()
	resx, resy := CURVE.ScalarMult(a.X, a.Y, bns)
	p.X = resx
	p.Y = resy
	return p
}

/*
ScalarBaseMult returns the Scalar Multiplication by the base generator.
*/
func (p *P256) ScalarBaseMult(n *big.Int) *P256 {
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = ffmath.Mod(n, CURVE.N)
	bns := n.Bytes()
	resx, resy := CURVE.ScalarBaseMult(bns)
	p.X = resx
	p.Y = resy
	return p
}

/*
Multiply actually is reponsible for the addition of elliptic curve points.
The name here is to maintain compatibility with bn128 interface.
This algorithm verifies if the given elliptic curve points are equal, in which case it
returns the result of Double function, otherwise it returns the result of Add function.
*/
func (p *P256) Multiply(a, b *P256) *P256 {
	if a.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p
	} else if b.IsZero() {
		p.X = a.X
		p.Y = a.Y
		return p
	}
	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		resx, resy := CURVE.Double(a.X, a.Y)
		p.X = resx
		p.Y = resy
		return p
	}
	resx, resy := CURVE.Add(a.X, a.Y, b.X, b.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
SetInfinity sets the given elliptic curve point to the point at infinity.
*/
func (p *P256) SetInfinity() *P256 {
	p.X = nil
	p.Y = nil
	return p
}

/*
String returns the readable representation of the given elliptic curve point, i.e.
the tuple formed by X and Y coordinates.
*/
func (p *P256) String() string {
	return "P256(" + p.X.String() + "," + p.Y.String() + ")"
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
		x, _ := util.HashToInt(buffer,sha256.New)
		x = ffmath.Mod(x, CURVE.P)
		fx, _ := F(x)
		fx = ffmath.Mod(fx, CURVE.P)
		y := fx.ModSqrt(fx, CURVE.P)
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
	x3p7 = ffmath.Mod(x3p7, CURVE.P)
	// Compute x^3
	x3p7 = ffmath.Multiply(x3p7, x)
	x3p7 = ffmath.Mod(x3p7, CURVE.P)
	// Compute X^3 + 7
	x3p7 = ffmath.Add(x3p7, new(big.Int).SetInt64(7))
	x3p7 = ffmath.Mod(x3p7, CURVE.P)
	return x3p7, nil
}

/*
IsOnCurve returns TRUE if and only if p has coordinates X and Y that satisfy the
Elliptic Curve equation: y^2 = x^3 + 7.
*/
func (p *P256) IsOnCurve() bool {
	// y² = x³ + 7
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, CURVE.P)

	x3 := new(big.Int).Mul(p.X, p.X)
	x3.Mul(x3, p.X)

	x3.Add(x3, new(big.Int).SetInt64(7))
	x3.Mod(x3, CURVE.P)

	return x3.Cmp(y2) == 0
}

