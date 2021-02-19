package bp_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"ZKSneak/ZKSneak-crypto/util"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

/*
powerOf returns a vector composed by powers of x.
*/
func powerOf(x *big.Int, n int64) []*big.Int {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	current := BigFromBase10("1")
	i = 0
	for i < n {
		result[i] = current
		current = ffmath.MultiplyMod(current, x, ORDER)
		i = i + 1
	}
	return result
}

func HashBP(A, S *bn256.G1Affine) (*big.Int, *big.Int, error) {
	// H(A,S)
	buffer := util.ContactBytes(bn128.ToBytes(A), bn128.ToBytes(S))
	output1, _ := util.CalHash(buffer, sha256.New)
	result1 := new(big.Int).SetBytes(output1)
	// H(A,S,H(A,S))
	buffer2 := util.ContactBytes(buffer, result1.Bytes())
	output2, _ := util.CalHash(buffer2, sha256.New)
	result2 := new(big.Int).SetBytes(output2)
	return result1, result2, nil
}

/*
VectorExp computes Prod_i^n{a[i]^b[i]}.
*/
func VectorExp(a []*bn256.G1Affine, b []*big.Int) (*bn256.G1Affine, error) {
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
	result = bn128.GetG1InfinityPoint()
	for i < n {
		result = bn128.G1AffineMul(result, new(bn256.G1Affine).ScalarMultiplication(a[i], b[i]))
		i = i + 1
	}
	return result, nil
}

/*
ScalarProduct return the inner product between a and b.
*/
func ScalarProduct(a, b []*big.Int) (*big.Int, error) {
	var (
		result  *big.Int
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
		result = ffmath.Mod(result, ORDER)
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
func BigFromBase10(value string) *big.Int {
	i, _ := new(big.Int).SetString(value, 10)
	return i
}

/*
CommitG1 method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func CommitG1(x, r *big.Int, h *bn256.G1Affine) (*bn256.G1Affine, error) {
	var C = bn128.G1ScalarBaseMult(x)
	Hr := new(bn256.G1Affine).ScalarMultiplication(h, r)
	C = bn128.G1AffineMul(C, Hr)
	return C, nil
}

/*
Decompose receives as input a bigint x and outputs an array of integers such that
x = sum(xi.u^i), i.e. it returns the decomposition of x into base u.
*/
func Decompose(x *big.Int, u int64, l int64) ([]int64, error) {
	var (
		result []int64
		i      int64
	)
	result = make([]int64, l)
	i = 0
	for i < l {
		result[i] = ffmath.Mod(x, new(big.Int).SetInt64(u)).Int64()
		x = new(big.Int).Div(x, new(big.Int).SetInt64(u))
		i = i + 1
	}
	return result, nil
}
