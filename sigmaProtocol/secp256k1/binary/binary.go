package binary

import (
	"PrivaL-crypto/commitment/secp256k1/pedersen"
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/ffmath"
	"errors"
	"math/big"
)

type P256 = zp256.P256

func Prove(m int, r *big.Int) (ca *P256, cb *P256, f *big.Int, za *big.Int, zb *big.Int, err error) {
	if m != 0 && m != 1 {
		return nil, nil, nil, nil, nil, errors.New("invalid m, m should be binary")
	}
	// a,s,t \gets_R \mathbb{Z}_p
	a := zp256.RandomValue()
	s := zp256.RandomValue()
	t := zp256.RandomValue()
	ca = pedersen.Commit(a, s, zp256.Base(), zp256.H)
	cb = pedersen.Commit(ffmath.Multiply(a, big.NewInt(int64(m))), t, zp256.Base(), zp256.H)
	// challenge
	x := HashChallenge(ca, cb)
	// f = mx + a
	f = ffmath.AddMod(ffmath.Multiply(x, big.NewInt(int64(m))), a, Order)
	// za = rx + s
	za = ffmath.AddMod(ffmath.MultiplyMod(r, x, Order), s, Order)
	// zb = r(x - f) + t
	zb = ffmath.SubMod(x, f, Order)
	zb = ffmath.MultiplyMod(r, zb, Order)
	zb = ffmath.AddMod(zb, t, Order)
	return ca, cb, f, za, zb, nil
}

func Verify(c, ca, cb *P256, f, za, zb *big.Int) bool {
	// c^x ca == Com(f,za)
	r1 := pedersen.Commit(f, za, zp256.Base(), zp256.H)
	// challenge
	x := HashChallenge(ca, cb)
	l1 := zp256.Add(zp256.ScalarMult(c, x), ca)
	l1r1 := zp256.Equal(l1, r1)
	if !l1r1 {
		return false
	}
	// c^{x-f} cb == Com(0,zb)
	r2 := pedersen.Commit(big.NewInt(0), zb, zp256.Base(), zp256.H)
	l2 := zp256.Add(zp256.ScalarMult(c, ffmath.SubMod(x, f, Order)), cb)
	l2r2 := zp256.Equal(l2, r2)
	if !l2r2 {
		return false
	}
	return true
}
