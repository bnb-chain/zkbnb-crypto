package bulletProofs

import (
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

/*
CommitG1 method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func CommitG1(x, r *big.Int, g, h *P256) (*P256, error) {
	C := zp256.ScalarMul(g, x)
	Hr := zp256.ScalarMul(h, r)
	C = zp256.Add(C, Hr)
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
	uInt := big.NewInt(u)
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
func HashBP(A, S *P256) (*big.Int, *big.Int, error) {

	var buffer bytes.Buffer
	// H(A,S)
	buffer.WriteString(A.String())
	buffer.WriteString(S.String())
	a, err := util.HashToInt(buffer, zmimc.Hmimc)
	if err != nil {
		return nil, nil, err
	}

	// H(A,S,H(A,S))
	buffer.Reset()
	buffer.WriteString(A.String())
	buffer.WriteString(S.String())
	buffer.WriteString(a.String())
	b, _ := util.HashToInt(buffer, zmimc.Hmimc)
	if err != nil {
		return nil, nil, err
	}

	return ffmath.Mod(a, Order), ffmath.Mod(b, Order), nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*P256, P *P256, c *big.Int, n int64) (result *big.Int, err error) {
	var buffer bytes.Buffer
	buffer.Write(P.Bytes())
	for i := int64(0); i < n; i++ {
		buffer.Write(g[i].Bytes())
		buffer.Write(h[i].Bytes())
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
func updateGenerators(Hh []*P256, y *big.Int, N int64) []*P256 {
	var (
		i int64
	)
	// Compute h'
	// h'_i = h_i^{y^{-i + 1}}
	hprimes := make([]*P256, N)
	// Switch generators
	yinv := ffmath.ModInverse(y, Order)
	expy := yinv
	hprimes[0] = Hh[0]
	i = 1
	for i < N {
		hprimes[i] = zp256.ScalarMul(Hh[i], expy)
		expy = ffmath.MultiplyMod(expy, yinv, Order)
		i = i + 1
	}
	return hprimes
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
*/
func delta(y, z *big.Int, N int64) *big.Int {
	var (
		result *big.Int
	)
	// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
	z2 := ffmath.MultiplyMod(z, z, Order)
	z3 := ffmath.MultiplyMod(z2, z, Order)

	// < 1^n, y^n >
	v1, _ := VectorCopy(new(big.Int).SetInt64(1), N)
	vy := powerOfVec(y, N)
	sp1y, _ := ScalarVecMul(v1, vy)

	// < 1^n, 2^n >
	p2n := powerOfVec(new(big.Int).SetInt64(2), N)
	sp12, _ := ScalarVecMul(v1, p2n)

	result = ffmath.SubMod(z, z2, Order)
	result = ffmath.MultiplyMod(result, sp1y, Order)
	result = ffmath.SubMod(result, ffmath.MultiplyMod(z3, sp12, Order), Order)

	return result
}
