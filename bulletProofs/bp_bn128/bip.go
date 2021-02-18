package bp_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"ZKSneak/ZKSneak-crypto/util"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"math/big"
	"strconv"
)

var SEEDU = "ZKSneakBulletproofsSetupU"

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	N  int64
	Cc *big.Int
	Uu *bn256.G1Affine
	H  *bn256.G1Affine
	Gg []*bn256.G1Affine
	Hh []*bn256.G1Affine
	P  *bn256.G1Affine
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	N      int64
	Ls     []*bn256.G1Affine
	Rs     []*bn256.G1Affine
	U      *bn256.G1Affine
	P      *bn256.G1Affine
	Gg     *bn256.G1Affine
	Hh     *bn256.G1Affine
	A      *big.Int
	B      *big.Int
	Params InnerProductParams
}

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(H *bn256.G1Affine, g, h []*bn256.G1Affine, c *big.Int, N int64) (InnerProductParams, error) {
	var params InnerProductParams

	if N <= 0 {
		return params, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		params.H, _ = bn128.HashToG1(SEEDH)
	} else {
		params.H = H
	}
	if g == nil {
		params.Gg = make([]*bn256.G1Affine, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Gg[i], _ = bn128.HashToG1(SEEDH + "g" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Gg = g
	}
	if h == nil {
		params.Hh = make([]*bn256.G1Affine, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Hh[i], _ = bn128.HashToG1(SEEDH + "h" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Hh = h
	}
	params.Cc = c
	params.Uu, _ = bn128.HashToG1(SEEDU)
	infinity := new(bn256.G1Affine)
	infinity.X.SetZero()
	infinity.Y.SetZero()
	params.P = infinity

	return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*big.Int, P *bn256.G1Affine, params InnerProductParams) (InnerProductProof, error) {
	var (
		proof InnerProductProof
		n, m  int64
		Ls    []*bn256.G1Affine
		Rs    []*bn256.G1Affine
	)

	n = int64(len(a))
	m = int64(len(b))

	if n != m {
		return proof, errors.New("size of first array argument must be equal to the second")
	}

	// Fiat-Shamir:
	// x = Hash(g,h,P,c)
	x, _ := hashIP(params.Gg, params.Hh, P, params.Cc, params.N)
	// Pprime = P.u^(x.c)
	ux := new(bn256.G1Affine).ScalarMultiplication(params.Uu, x)
	uxc := new(bn256.G1Affine).ScalarMultiplication(ux, params.Cc)
	PP := bn128.G1AffineMul(P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = PP
	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*big.Int, g, h []*bn256.G1Affine, u, P *bn256.G1Affine, n int64, Ls, Rs []*bn256.G1Affine) InnerProductProof {
	var (
		proof                            InnerProductProof
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             *bn256.G1Affine
		gprime, hprime, gprime2, hprime2 []*bn256.G1Affine
		aprime, bprime, aprime2, bprime2 []*big.Int
	)

	if n == 1 {
		// recursion end
		proof.A = a[0]
		proof.B = b[0]
		proof.Gg = g[0]
		proof.Hh = h[0]
		proof.P = P
		proof.U = u
		proof.Ls = Ls
		proof.Rs = Rs

	} else {
		// recursion

		// nprime := n / 2
		nprime := n / 2 // (20)

		// Compute cL = < a[:n'], b[n':] >                                    // (21)
		cL, _ = ScalarProduct(a[:nprime], b[nprime:])
		// Compute cR = < a[n':], b[:n'] >                                    // (22)
		cR, _ = ScalarProduct(a[nprime:], b[:nprime])
		// Compute L = g[n':]^(a[:n']).h[:n']^(b[n':]).u^cL                   // (23)
		L, _ = VectorExp(g[nprime:], a[:nprime])
		Lh, _ = VectorExp(h[:nprime], b[nprime:])
		L = bn128.G1AffineMul(L, Lh)
		L = bn128.G1AffineMul(L, new(bn256.G1Affine).ScalarMultiplication(u, cL))

		// Compute R = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
		R, _ = VectorExp(g[:nprime], a[nprime:])
		Rh, _ = VectorExp(h[nprime:], b[:nprime])
		R = bn128.G1AffineMul(R, Rh)
		R = bn128.G1AffineMul(R, new(bn256.G1Affine).ScalarMultiplication(u, cR))

		// Fiat-Shamir:                                                       // (26)
		x, _, _ = HashBP(L, R)
		xinv = ffmath.ModInverse(x, ORDER)

		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		gprime = vectorScalarExp(g[:nprime], xinv)
		gprime2 = vectorScalarExp(g[nprime:], x)
		gprime, _ = VectorECAdd(gprime, gprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		hprime = vectorScalarExp(h[:nprime], x)
		hprime2 = vectorScalarExp(h[nprime:], xinv)
		hprime, _ = VectorECAdd(hprime, hprime2)

		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = ffmath.Mod(ffmath.Multiply(x, x), ORDER)
		x2inv = ffmath.ModInverse(x2, ORDER)
		Pprime = new(bn256.G1Affine).ScalarMultiplication(L, x2)
		Pprime = bn128.G1AffineMul(Pprime, P)
		Pprime = bn128.G1AffineMul(Pprime, new(bn256.G1Affine).ScalarMultiplication(R, x2inv))

		// Compute a' = a[:n'].x      + a[n':].x^(-1)                         // (33)
		aprime, _ = VectorScalarMul(a[:nprime], x)
		aprime2, _ = VectorScalarMul(a[nprime:], xinv)
		aprime, _ = VectorAdd(aprime, aprime2)
		// Compute b' = b[:n'].x^(-1) + b[n':].x                              // (34)
		bprime, _ = VectorScalarMul(b[:nprime], xinv)
		bprime2, _ = VectorScalarMul(b[nprime:], x)
		bprime, _ = VectorAdd(bprime, bprime2)

		Ls = append(Ls, L)
		Rs = append(Rs, R)
		// recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
		proof = computeBipRecursive(aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs)
	}
	proof.N = n
	return proof
}

/*
Verify is responsible for the verification of the Inner Product Proof.
*/
func (proof InnerProductProof) Verify() (bool, error) {

	logn := len(proof.Ls)
	var (
		x, xinv, x2, x2inv                   *big.Int
		ngprime, nhprime, ngprime2, nhprime2 []*bn256.G1Affine
	)

	gprime := proof.Params.Gg
	hprime := proof.Params.Hh
	Pprime := proof.Params.P
	nprime := proof.N
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                        // (20)
		x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
		xinv = ffmath.ModInverse(x, ORDER)
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(gprime[:nprime], xinv)
		ngprime2 = vectorScalarExp(gprime[nprime:], x)
		gprime, _ = VectorECAdd(ngprime, ngprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(hprime[:nprime], x)
		nhprime2 = vectorScalarExp(hprime[nprime:], xinv)
		hprime, _ = VectorECAdd(nhprime, nhprime2)
		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = ffmath.Mod(ffmath.Multiply(x, x), ORDER)
		x2inv = ffmath.ModInverse(x2, ORDER)
		Pprime  = bn128.G1AffineMul(Pprime, new(bn256.G1Affine).ScalarMultiplication(proof.Ls[i], x2))
		Pprime  = bn128.G1AffineMul(Pprime, new(bn256.G1Affine).ScalarMultiplication(proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := ffmath.Multiply(proof.A, proof.B)
	ab = ffmath.Mod(ab, ORDER)
	// Compute right hand side
	rhs := new(bn256.G1Affine).ScalarMultiplication(gprime[0], proof.A)
	hb := new(bn256.G1Affine).ScalarMultiplication(hprime[0], proof.B)
	rhs = bn128.G1AffineMul(rhs, hb)
	rhs = bn128.G1AffineMul(rhs, new(bn256.G1Affine).ScalarMultiplication(proof.U, ab))
	// Compute inverse of left hand side
	nP := Pprime.Neg(Pprime)
	nP = bn128.G1AffineMul(nP, rhs)
	// If both sides are equal then nP must be zero                               // (17)
	c := nP.IsInfinity()

	return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*bn256.G1Affine, P *bn256.G1Affine, c *big.Int, n int64) (*big.Int, error) {
	digest := sha256.New()
	digest.Write([]byte(P.String()))

	for i := int64(0); i < n; i++ {
		digest.Write([]byte(g[i].String()))
		digest.Write([]byte(h[i].String()))
	}

	digest.Write([]byte(c.String()))
	output := digest.Sum(nil)
	tmp := output[0:]
	result, err := util.FromByteArray(tmp)

	return result, err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*bn256.G1Affine, a, b []*big.Int) *bn256.G1Affine {
	var (
		result *bn256.G1Affine
	)

	ga, _ := VectorExp(g, a)
	hb, _ := VectorExp(h, b)
	result = bn128.G1AffineMul(ga, hb)
	return result
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []*bn256.G1Affine, b *big.Int) []*bn256.G1Affine {
	var (
		result []*bn256.G1Affine
		n      int64
	)
	n = int64(len(a))
	result = make([]*bn256.G1Affine, n)
	for i := int64(0); i < n; i++ {
		result[i] = new(bn256.G1Affine).ScalarMultiplication(a[i], b)
	}
	return result
}
