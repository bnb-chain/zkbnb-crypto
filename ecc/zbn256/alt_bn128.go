package zbn256

import (
	"ZKSneak-crypto/ffmath"
	"ZKSneak-crypto/util"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

var (
	Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	SeedH    = "ZKSneakBN128SetupH"
)

type G1Affine = bn256.G1Affine

func HashToG1(m string) (*G1Affine, error) {
	p, err := bn256.HashToCurveG1Svdw([]byte(m), []byte(m))
	return &p, err
}

func GetG1InfinityPoint() *G1Affine {
	p := new(G1Affine)
	p.X.SetZero()
	p.Y.SetZero()
	return p
}

func G1Add(a, b *G1Affine) *G1Affine {
	aJac := new(bn256.G1Jac).FromAffine(a)
	p := new(G1Affine).FromJacobian(aJac.AddMixed(b))
	return p
}

func G1ScalarMult(a *G1Affine, s *big.Int) *G1Affine {
	return new(G1Affine).ScalarMultiplication(a, s)
}

func G1ScalarHBaseMult(s *big.Int) *G1Affine {
	_, HAffine := GetG1TwoBaseAffine()
	return new(G1Affine).ScalarMultiplication(HAffine, s)
}

func G1ScalarBaseMult(s *big.Int) *G1Affine {
	base := G1BaseAffine()
	return new(G1Affine).ScalarMultiplication(base, s)
}

func G1BaseAffine() (*G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
	return &G1Affine
}

func GetG1TwoBaseAffine() (g *G1Affine, h *G1Affine) {
	_, _, G1Affine, _ := bn256.Generators()
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
	return ffmath.RandomValue(Order)
}
