package bp_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

/*
VectorCopy returns a vector composed by copies of a.
*/
func VectorCopy(a *big.Int, n int64) ([]*big.Int, error) {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	i = 0
	for i < n {
		result[i] = a
		i = i + 1
	}
	return result, nil
}

/*
VectorConvertToBig converts an array of int64 to an array of big.Int.
*/
func VectorConvertToBig(a []int64, n int64) ([]*big.Int, error) {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	i = 0
	for i < n {
		result[i] = new(big.Int).SetInt64(a[i])
		i = i + 1
	}
	return result, nil
}

/*
VectorAdd computes vector addition componentwisely.
*/
func VectorAdd(a, b []*big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.Add(a[i], b[i])
		result[i] = ffmath.Mod(result[i], ORDER)
		i = i + 1
	}
	return result, nil
}

/*
VectorSub computes vector addition componentwisely.
*/
func VectorSub(a, b []*big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.Sub(a[i], b[i])
		result[i] = ffmath.Mod(result[i], ORDER)
		i = i + 1
	}
	return result, nil
}

/*
VectorScalarMul computes vector scalar multiplication componentwisely.
*/
func VectorScalarMul(a []*big.Int, b *big.Int) ([]*big.Int, error) {
	var (
		result []*big.Int
		i, n   int64
	)
	n = int64(len(a))
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.Multiply(a[i], b)
		result[i] = ffmath.Mod(result[i], ORDER)
		i = i + 1
	}
	return result, nil
}

/*
VectorMul computes vector multiplication componentwisely.
*/
func VectorMul(a, b []*big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.Multiply(a[i], b[i])
		result[i] = ffmath.Mod(result[i], ORDER)
		i = i + 1
	}
	return result, nil
}

/*
VectorECMul computes vector EC addition componentwisely.
*/
func VectorECMul(a, b []*bn256.G1Affine) ([]*bn256.G1Affine, error) {
	var (
		result  []*bn256.G1Affine
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	result = make([]*bn256.G1Affine, n)
	i = 0
	for i < n {
		result[i] = bn128.G1AffineMul(a[i], b[i])
		i = i + 1
	}
	return result, nil
}
