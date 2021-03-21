package bp_bn128

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"math/big"
)

/*
VectorCopy returns a vector composed by copies of a.
*/
func VectorCopy(a *fr.Element, n int64) ([]*fr.Element, error) {
	var (
		i      int64
		result []*fr.Element
	)
	result = make([]*fr.Element, n)
	i = 0
	for i < n {
		result[i] = a
		i = i + 1
	}
	return result, nil
}

/*
VectorConvertToBig converts an array of int64 to an array of fr.Element.
*/
func VectorConvertToBig(a []int64, n int64) ([]*fr.Element, error) {
	var (
		i      int64
		result []*fr.Element
	)
	result = make([]*fr.Element, n)
	i = 0
	for i < n {
		result[i] = ffmath.FromBigInt(new(big.Int).SetInt64(a[i]))
		i = i + 1
	}
	return result, nil
}

/*
VectorAdd computes vector addition componentwisely.
*/
func VectorAdd(a, b []*fr.Element) ([]*fr.Element, error) {
	var (
		result  []*fr.Element
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*fr.Element, n)
	for i < n {
		result[i] = ffmath.Add(a[i], b[i])
		i = i + 1
	}
	return result, nil
}

/*
VectorSub computes vector addition componentwisely.
*/
func VectorSub(a, b []*fr.Element) ([]*fr.Element, error) {
	var (
		result  []*fr.Element
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*fr.Element, n)
	for i < n {
		result[i] = ffmath.Sub(a[i], b[i])
		i = i + 1
	}
	return result, nil
}

/*
VectorScalarMul computes vector scalar multiplication componentwisely.
*/
func VectorScalarMul(a []*fr.Element, b *fr.Element) ([]*fr.Element, error) {
	var (
		result []*fr.Element
		i, n   int64
	)
	n = int64(len(a))
	i = 0
	result = make([]*fr.Element, n)
	for i < n {
		result[i] = ffmath.Multiply(a[i], b)
		i = i + 1
	}
	return result, nil
}

/*
VectorMul computes vector multiplication componentwisely.
*/
func VectorMul(a, b []*fr.Element) ([]*fr.Element, error) {
	var (
		result  []*fr.Element
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*fr.Element, n)
	for i < n {
		result[i] = ffmath.Multiply(a[i], b[i])
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
		result[i] = zbn256.G1Add(a[i], b[i])
		i = i + 1
	}
	return result, nil
}
