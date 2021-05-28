package zecrey

import (
	"math/big"
	"zecrey-crypto/ecc/zp256"
)

// g^{\sum_{i=1}^n b_i} = InfinityPoint
func ProveSumZero(bs []*big.Int, G *P256) (U *P256, as []*big.Int, err error) {
	var (
		n int
	)
	if bs == nil || G == nil {
		return nil, nil, InvalidParams
	}
	n = len(bs)
	// get random vec
	as = RandomVec(uint(n))
	asSum := VecSum(as)
	// U = g^{\sum_{i=1}^n as[i]}
	U = zp256.ScalarMul(G, asSum)
	return U, as, nil
}

func VerifySumZero(c *big.Int, U *P256, zs []*big.Int, G *P256) (bool, error) {
	// check params
	if c == nil || U == nil || zs == nil || len(zs) == 0 || G == nil {
		return false, InvalidParams
	}
	// compute l = g^{\sum_{i=1}^n zs[i]}
	zsSum := VecSum(zs)
	l := zp256.ScalarMul(G, zsSum)
	// compute r = P \cdot U^c
	P := zp256.InfinityPoint()
	r := zp256.Add(P, zp256.ScalarMul(U, c))
	// verify l == r
	return zp256.Equal(l, r), nil
}

// C_{i,L}^{\Delta} = pk_i^r \wedge C_{i,R}^{\Delta} = g^{r_i} h^{b_i^{\Delta}}
func ProveValidEnc(pk, G, H *P256, r, bDelta *big.Int) (A, B *P256, as []*big.Int, err error) {
	// check params
	if pk == nil || G == nil || H == nil || r == nil || bDelta == nil {
		return nil, nil, nil, InvalidParams
	}
	// a_i \gets_R Z_p, i = 1,2
	as = RandomVec(2)
	// A = pk^{as[0]}
	A = zp256.ScalarMul(pk, as[0])
	// B = g^{as[0]} h^{as[1]}
	B = zp256.ScalarMul(G, as[0])
	B = zp256.Add(B, zp256.ScalarMul(H, as[1]))
	return A, B, as, nil
}

func VerifyValidEnc(c *big.Int, C *ElGamalEnc, A, B *P256, zs []*big.Int, pk, G, H *P256) (bool, error) {
	// check params
	if c == nil || C == nil || C.CL == nil || C.CR == nil ||
		A == nil || B == nil || zs == nil || len(zs) != 2 ||
		pk == nil || G == nil || H == nil {
		return false, InvalidParams
	}
	// compute pk^{zs[0]}
	l1 := zp256.ScalarMul(pk, zs[0])
	// compute A C_L^{c}
	r1 := zp256.ScalarMul(C.CL, c)
	r1 = zp256.Add(A, r1)
	res1 := zp256.Equal(l1, r1)
	if !res1 {
		return false, nil
	}
	// compute g^{zs[0]} h^{zs[1]}
	l2 := zp256.ScalarMul(G, zs[0])
	l2 = zp256.Add(l2, zp256.ScalarMul(H, zs[1]))
	// compute B C_R^{c}
	r2 := zp256.ScalarMul(C.CR, c)
	r2 = zp256.Add(B, r2)
	return zp256.Equal(l2, r2), nil
}
