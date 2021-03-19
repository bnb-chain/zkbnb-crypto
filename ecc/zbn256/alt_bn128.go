package zbn256

import (
	"ZKSneak-crypto/math"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"math/big"
)

var (
	ORDER, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	SEEDH    = "ZKSneakBN128SetupH"
)

type G1Affine = bn256.G1Affine

func HashToG1(m string) (*G1Affine, error) {
	p, err := bn256.HashToCurveG1Svdw([]byte(m), []byte(m))
	return &p, err
}

/*
F receives a big integer x as input and return x^3 + 3 mod ORDER.
*/
func F(x *big.Int) (*big.Int, error) {
	// Compute x^2
	x3p3 := math.Multiply(x, x)
	x3p3 = math.Mod(x3p3, ORDER)
	// Compute x^3
	x3p3 = math.Multiply(x3p3, x)
	x3p3 = math.Mod(x3p3, ORDER)
	// Compute X^3 + 3
	x3p3 = math.Add(x3p3, new(big.Int).SetInt64(7))
	x3p3 = math.Mod(x3p3, ORDER)
	return x3p3, nil
}

func GetG1InfinityPoint() *G1Affine {
	p := new(G1Affine)
	p.X.SetZero()
	p.Y.SetZero()
	return p
}

func G1AffineMul(a, b *G1Affine) *G1Affine {
	aJac := new(bn256.G1Jac).FromAffine(a)
	p := new(G1Affine).FromJacobian(aJac.AddMixed(b))
	return p
}

func G1ScalarMult(a *G1Affine, s *fr.Element) *G1Affine {
	return new(G1Affine).ScalarMultiplication(a, ffmath.ToBigInt(s))
}

func G1ScalarBaseMult(s *fr.Element) *G1Affine {
	base := GetG1BaseAffine()
	return new(G1Affine).ScalarMultiplication(base, ffmath.ToBigInt(s))
}

func G1ScalarMultInt(a *G1Affine, s *big.Int) *G1Affine {
	return new(G1Affine).ScalarMultiplication(a, s)
}

func G1ScalarHBaseMultInt(s *big.Int) *G1Affine {
	_, HAffine := GetG1TwoBaseAffine()
	return new(G1Affine).ScalarMultiplication(HAffine, s)
}

func G1ScalarBaseMultInt(s *big.Int) *G1Affine {
	base := GetG1BaseAffine()
	return new(G1Affine).ScalarMultiplication(base, s)
}

func G1ScalarHBaseMult(s *fr.Element) *G1Affine {
	_, HAffine := GetG1TwoBaseAffine()
	return new(G1Affine).ScalarMultiplication(HAffine, ffmath.ToBigInt(s))
}

func GetG1BaseAffine() (*G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
	return &G1Affine
}

func GetG1TwoBaseAffine() (g *G1Affine, h *G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
	HAffine, _ := HashToG1(SEEDH)
	return &G1Affine, HAffine
}

func Neg(s *G1Affine) *G1Affine {
	return new(G1Affine).Neg(s)
}

func ToBytes(a *G1Affine) []byte {
	aXFixBytes := a.X.Bytes()
	aYFixBytes := a.Y.Bytes()
	aXBytes := aXFixBytes[:]
	aYBytes := aYFixBytes[:]
	return util.ContactBytes(aXBytes, aYBytes)
}

func VecToBytes(arr []*G1Affine) []byte {
	var res []byte
	for _, value := range arr {
		res = util.ContactBytes(res, ToBytes(value))
	}
	return res
}
