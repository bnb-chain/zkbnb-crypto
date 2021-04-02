package bulletProofs

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/ffmath"
	"errors"
	"math/big"
)

/*
SampleRandomVector generates a vector composed by random big numbers.
*/
func RandomVector(N int64) []*big.Int {
	s := make([]*big.Int, N)
	for i := int64(0); i < N; i++ {
		s[i] = zp256.RandomValue()
	}
	return s
}

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
func ToBigIntVec(a []int64, n int64) ([]*big.Int, error) {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	i = 0
	for i < n {
		result[i] = big.NewInt(a[i])
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
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.SubMod(a[i], b[i], Order)
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
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.MultiplyMod(a[i], b[i], Order)
		i = i + 1
	}
	return result, nil
}

/*
ScalarProduct return the inner product between a and b.
*/
func ScalarVecMul(a, b []*big.Int) (*big.Int, error) {
	var (
		result  *big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	i = 0
	result = big.NewInt(0)
	for i < n {
		ab := ffmath.MultiplyMod(a[i], b[i], Order)
		result = ffmath.AddMod(result, ab, Order)
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
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = ffmath.AddMod(a[i], b[i], Order)
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
		result[i] = ffmath.MultiplyMod(a[i], b, Order)
		i = i + 1
	}
	return result, nil
}

/*
VectorECMul computes vector EC addition componentwisely.
*/
func VectorECAdd(a, b []*P256) ([]*P256, error) {
	var (
		result  []*P256
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	result = make([]*P256, n)
	i = 0
	for i < n {
		result[i] = zp256.Add(a[i], b[i])
		i = i + 1
	}
	return result, nil
}

/*
VectorExp computes Prod_i^n{a[i]^b[i]}.
*/
func VectorExp(a []*P256, b []*big.Int) (result *P256, err error) {
	n := int64(len(a))
	m := int64(len(b))
	if n < m {
		return nil, errors.New("size of first argument is different from size of second argument")
	}
	i := int64(0)
	result = zp256.InfinityPoint()
	for i < m {
		result.Multiply(result, zp256.ScalarMult(a[i], b[i]))
		i = i + 1
	}
	return result, nil
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []*P256, b *big.Int) []*P256 {
	var (
		result []*P256
		n      int64
	)
	n = int64(len(a))
	result = make([]*P256, n)
	for i := int64(0); i < n; i++ {
		result[i] = zp256.ScalarMult(a[i], b)
	}
	return result
}
