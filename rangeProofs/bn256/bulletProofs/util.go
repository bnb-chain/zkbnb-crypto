package bp_bn128

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"math/big"
)

/*
powerOf returns a vector composed by powers of x.
*/
func powerOf(x *fr.Element, n int64) []*fr.Element {
	var (
		i      int64
		result []*fr.Element
	)
	result = make([]*fr.Element, n)
	current := BigFromBase10("1")
	i = 0
	for i < n {
		result[i] = current
		current = ffmath.Multiply(current, x)
		i = i + 1
	}
	return result
}

func HashBP(A, S *bn256.G1Affine) (*fr.Element, *fr.Element, error) {
	// H(A,S)
	buffer := util.ContactBytes(zbn256.ToBytes(A), zbn256.ToBytes(S))
	output1, _ := util.CalHash(buffer, sha256.New)
	result1 := new(big.Int).SetBytes(output1)
	// H(A,S,H(A,S))
	buffer2 := util.ContactBytes(buffer, result1.Bytes())
	output2, _ := util.CalHash(buffer2, sha256.New)
	result2 := new(fr.Element).SetBytes(output2)
	return ffmath.FromBigInt(result1), result2, nil
}

/*
VectorExp computes Prod_i^n{a[i]^b[i]}.
*/
func VectorExp(a []*bn256.G1Affine, b []*fr.Element) (*bn256.G1Affine, error) {
	var (
		result  *bn256.G1Affine
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = zbn256.GetG1InfinityPoint()
	for i < n {
		result = zbn256.G1Add(result, zbn256.G1ScalarMult(a[i], b[i]))
		i = i + 1
	}
	return result, nil
}

/*
ScalarProduct return the inner product between a and b.
*/
func ScalarProduct(a, b []*fr.Element) (*fr.Element, error) {
	var (
		result  *fr.Element
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = BigFromBase10("0")
	for i < n {
		ab := ffmath.Multiply(a[i], b[i])
		result.Add(result, ab)
		i = i + 1
	}
	return result, nil
}

/*
IsPowerOfTwo returns true for arguments that are a power of 2, false otherwise.
https://stackoverflow.com/a/600306/844313
*/
func IsPowerOfTwo(x int64) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}

/*
Read big integer in base 10 from string.
*/
func BigFromBase10(value string) *fr.Element {
	i, _ := new(big.Int).SetString(value, 10)
	return ffmath.FromBigInt(i)
}

/*
CommitG1 method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func CommitG1(x, r *fr.Element, h *bn256.G1Affine) (*bn256.G1Affine, error) {
	var C = zbn256.G1ScalarHBaseMult(x)
	Hr := zbn256.G1ScalarMult(h, r)
	C = zbn256.G1Add(C, Hr)
	return C, nil
}

/*
Decompose receives as input a bigint x and outputs an array of integers such that
x = sum(xi.u^i), i.e. it returns the decomposition of x into base u.
*/
func Decompose(x *fr.Element, u int64, l int64) ([]int64, error) {
	var (
		result []int64
		i      int64
	)
	result = make([]int64, l)
	i = 0
	for i < l {
		result[i] = math.Mod(ffmath.ToBigInt(x), big.NewInt(u)).Int64()
		x = ffmath.Div(x, new(fr.Element).SetUint64(uint64(u)))
		i = i + 1
	}
	return result, nil
}
