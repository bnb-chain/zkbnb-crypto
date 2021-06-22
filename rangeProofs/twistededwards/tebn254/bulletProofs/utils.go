package bulletProofs

import (
	"bytes"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

/*
CommitG1 method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func CommitG1(x, r *big.Int, g, h *Point) (*Point, error) {
	C := curve.ScalarMul(g, x)
	Hr := curve.ScalarMul(h, r)
	C.Add(C, Hr)
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
	uInt := big.NewInt(int64(u))
	i = 0
	for i < l {
		result[i] = ffmath.Mod(x, uInt).Int64()
		x = ffmath.Div(x, uInt)
		i = i + 1
	}
	return result, nil
}

/*
Hash is responsible for the computing a Zp element given elements from GT and G1.
*/
func HashBP(A, S *Point) (*big.Int, *big.Int, error) {
	ABytes := curve.ToBytes(A)
	SBytes := curve.ToBytes(S)
	var buffer bytes.Buffer
	// Waste(A,S)
	buffer.Write(ABytes)
	buffer.Write(SBytes)
	a, err := util.HashToInt(buffer, zmimc.Hmimc)
	if err != nil {
		return nil, nil, err
	}

	// Waste(A,S,Waste(A,S))
	buffer.Reset()
	buffer.Write(ABytes)
	buffer.Write(SBytes)
	buffer.Write(a.Bytes())

	b, err := util.HashToInt(buffer, zmimc.Hmimc)
	if err != nil {
		return nil, nil, err
	}

	return ffmath.Mod(a, Order), ffmath.Mod(b, Order), nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*Point, P *Point, c *big.Int, n int64) (result *big.Int, err error) {
	var buffer bytes.Buffer
	buffer.Write(curve.ToBytes(P))
	for i := int64(0); i < n; i++ {
		buffer.Write(curve.ToBytes(g[i]))
		buffer.Write(curve.ToBytes(h[i]))
	}
	buffer.Write(c.Bytes())
	result, err = util.HashToInt(buffer, zmimc.Hmimc)

	return ffmath.Mod(result, Order), err
}

/*
IsPowerOfTwo returns true for arguments that are a power of 2, false otherwise.
https://stackoverflow.com/a/600306/844313
*/
func IsPowerOfTwo(x int64) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}

/*
powerOf returns a vector composed by powers of x.
*/
func powerOfVec(y *big.Int, n int64) []*big.Int {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	current := big.NewInt(1)
	i = 0
	for i < n {
		result[i] = current
		current = ffmath.MultiplyMod(y, current, Order)
		i = i + 1
	}
	return result
}

/*
updateGenerators is responsible for computing generators in the following format:
[h_1, h_2^(y^-1), ..., h_n^(y^(-n+1))], where [h_1, h_2, ..., h_n] is the original
vector of generators. This method is used both by prover and verifier. After this
update we have that A is a vector commitments to (aL, aR . y^n). Also S is a vector
commitment to (sL, sR . y^n).
*/
func updateGenerators(Hh []*Point, y *big.Int, N int64) []*Point {
	var (
		i int64
	)
	// Compute h'
	// h'_i = h_i^{y^{-i + 1}}
	hprimes := make([]*Point, N)
	// Switch generators
	yinv := ffmath.ModInverse(y, Order)
	expy := yinv
	hprimes[0] = Hh[0]
	i = 1
	for i < N {
		hprimes[i] = curve.ScalarMul(Hh[i], expy)
		expy = ffmath.MultiplyMod(expy, yinv, Order)
		i = i + 1
	}
	return hprimes
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
*/
func delta(y, z *big.Int, N int64) (*big.Int, error) {
	var (
		result *big.Int
	)
	// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
	z2 := ffmath.MultiplyMod(z, z, Order)
	z3 := ffmath.MultiplyMod(z2, z, Order)

	// < 1^n, y^n >
	v1, err := VectorCopy(new(big.Int).SetInt64(1), N)
	if err != nil {
		return nil, err
	}
	vy := powerOfVec(y, N)
	sp1y, err := ScalarVecMul(v1, vy)
	if err != nil {
		return nil, err
	}

	// < 1^n, 2^n >
	p2n := powerOfVec(big.NewInt(2), N)
	sp12, err := ScalarVecMul(v1, p2n)
	if err != nil {
		return nil, err
	}

	result = ffmath.Sub(z, z2)
	result = ffmath.Multiply(result, sp1y)
	result = ffmath.SubMod(result, ffmath.Multiply(z3, sp12), Order)

	return result, nil
}
