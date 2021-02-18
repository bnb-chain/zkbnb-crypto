package bn128

import (
	"ZKSneak/ZKSneak-crypto/ffmath"
	"ZKSneak/ZKSneak-crypto/util"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

var (
	ORDER, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	SEEDH    = "ZKSneakBulletProofsSetupH"
)

func HashToG1(m string) (*bn256.G1Affine, error) {
	p, err := bn256.HashToCurveG1Svdw([]byte(m), []byte(m))
	return &p, err
}

/*
F receives a big integer x as input and return x^3 + 3 mod ORDER.
*/
func F(x *big.Int) (*big.Int, error) {
	// Compute x^2
	x3p3 := ffmath.Multiply(x, x)
	x3p3 = ffmath.Mod(x3p3, ORDER)
	// Compute x^3
	x3p3 = ffmath.Multiply(x3p3, x)
	x3p3 = ffmath.Mod(x3p3, ORDER)
	// Compute X^3 + 3
	x3p3 = ffmath.Add(x3p3, new(big.Int).SetInt64(7))
	x3p3 = ffmath.Mod(x3p3, ORDER)
	return x3p3, nil
}

func GetG1InfinityPoint() *bn256.G1Affine {
	p := new(bn256.G1Affine)
	p.X.SetZero()
	p.Y.SetZero()
	return p
}

func G1AffineMul(a, b *bn256.G1Affine) *bn256.G1Affine {
	aJac := new(bn256.G1Jac).FromAffine(a)
	p := new(bn256.G1Affine).FromJacobian(aJac.AddMixed(b))
	return p
}

func G1ScalarBaseMult(s *big.Int) *bn256.G1Affine {
	_, _, G1Affine, _ := bn256.Generators()
	return new(bn256.G1Affine).ScalarMultiplication(&G1Affine, s)
}

func GetG1BaseAffine() (*bn256.G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
	return &G1Affine
}

func GetG1TwoBaseAffine() (*bn256.G1Affine, *bn256.G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
	HAffine, _ := HashToG1(SEEDH)
	return &G1Affine, HAffine
}

func ToBytes(a *bn256.G1Affine) []byte {
	aXFixBytes := a.X.Bytes()
	aYFixBytes := a.Y.Bytes()
	aXBytes := aXFixBytes[:]
	aYBytes := aYFixBytes[:]
	return util.ContactBytes(aXBytes, aYBytes)
}
