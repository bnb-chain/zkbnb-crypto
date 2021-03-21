package bp_bn128

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"strconv"
)

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(H *bn256.G1Affine, g, h []*bn256.G1Affine, c *fr.Element, N int64) (InnerProductParams, error) {
	var params InnerProductParams

	if N <= 0 {
		return params, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		_, params.H = zbn256.GetG1TwoBaseAffine()
	} else {
		params.H = H
	}
	if g == nil {
		params.Gg = make([]*bn256.G1Affine, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Gg[i], _ = zbn256.HashToG1(SEEDH + "g" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Gg = g
	}
	if h == nil {
		params.Hh = make([]*bn256.G1Affine, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Hh[i], _ = zbn256.HashToG1(SEEDH + "h" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Hh = h
	}
	params.Cc = c
	params.Uu, _ = zbn256.HashToG1(SEEDU)
	params.P = zbn256.GetG1InfinityPoint()

	return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*fr.Element, P *bn256.G1Affine, params InnerProductParams) (InnerProductProof, error) {
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
	ux := zbn256.G1ScalarMult(params.Uu, x)
	uxc := zbn256.G1ScalarMult(ux, params.Cc)
	PP := zbn256.G1Add(P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = PP
	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*fr.Element, g, h []*bn256.G1Affine, u, P *bn256.G1Affine, n int64, Ls, Rs []*bn256.G1Affine) InnerProductProof {
	var (
		proof                            InnerProductProof
		cL, cR, x, xinv, x2, x2inv       *fr.Element
		L, R, Lh, Rh, Pprime             *bn256.G1Affine
		gprime, hprime, gprime2, hprime2 []*bn256.G1Affine
		aprime, bprime, aprime2, bprime2 []*fr.Element
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
		L = zbn256.G1Add(L, Lh)
		L = zbn256.G1Add(L, zbn256.G1ScalarMult(u, cL))

		// Compute r = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
		R, _ = VectorExp(g[:nprime], a[nprime:])
		Rh, _ = VectorExp(h[nprime:], b[:nprime])
		R = zbn256.G1Add(R, Rh)
		R = zbn256.G1Add(R, zbn256.G1ScalarMult(u, cR))

		// Fiat-Shamir:                                                       // (26)
		x, _, _ = HashBP(L, R)
		xinv = ffmath.Inverse(x)

		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		gprime = vectorScalarExp(g[:nprime], xinv)
		gprime2 = vectorScalarExp(g[nprime:], x)
		gprime, _ = VectorECMul(gprime, gprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		hprime = vectorScalarExp(h[:nprime], x)
		hprime2 = vectorScalarExp(h[nprime:], xinv)
		hprime, _ = VectorECMul(hprime, hprime2)

		// Compute P' = L^(x^2).P.r^(x^-2)                                    // (31)
		x2 = ffmath.Multiply(x, x)
		x2inv = ffmath.Inverse(x2)
		Pprime = zbn256.G1ScalarMult(L, x2)
		Pprime = zbn256.G1Add(Pprime, P)
		Pprime = zbn256.G1Add(Pprime, zbn256.G1ScalarMult(R, x2inv))

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
		x, xinv, x2, x2inv                   *fr.Element
		ngprime, nhprime, ngprime2, nhprime2 []*bn256.G1Affine
	)

	gprime := proof.Params.Gg
	hprime := proof.Params.Hh
	Pprime := proof.Params.P
	nprime := proof.N
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                        // (20)
		x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
		xinv = ffmath.Inverse(x)
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(gprime[:nprime], xinv)
		ngprime2 = vectorScalarExp(gprime[nprime:], x)
		gprime, _ = VectorECMul(ngprime, ngprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(hprime[:nprime], x)
		nhprime2 = vectorScalarExp(hprime[nprime:], xinv)
		hprime, _ = VectorECMul(nhprime, nhprime2)
		// Compute P' = L^(x^2).P.r^(x^-2)                                    // (31)
		x2 = ffmath.Multiply(x, x)
		x2inv = ffmath.Inverse(x2)
		Pprime = zbn256.G1Add(Pprime, zbn256.G1ScalarMult(proof.Ls[i], x2))
		Pprime = zbn256.G1Add(Pprime, zbn256.G1ScalarMult(proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := ffmath.Multiply(proof.A, proof.B)
	// Compute right hand side
	rhs := zbn256.G1ScalarMult(gprime[0], proof.A)
	hb := zbn256.G1ScalarMult(hprime[0], proof.B)
	rhs = zbn256.G1Add(rhs, hb)
	rhs = zbn256.G1Add(rhs, zbn256.G1ScalarMult(proof.U, ab))
	// Compute inverse of left hand side
	// If both sides are equal then nP must be zero                               // (17)
	c := rhs.Equal(Pprime)

	return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*bn256.G1Affine, P *bn256.G1Affine, c *fr.Element, n int64) (*fr.Element, error) {
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

	return ffmath.FromBigInt(result), err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*bn256.G1Affine, a, b []*fr.Element) *bn256.G1Affine {
	var (
		result *bn256.G1Affine
	)

	ga, _ := VectorExp(g, a)
	hb, _ := VectorExp(h, b)
	result = zbn256.G1Add(ga, hb)
	return result
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []*bn256.G1Affine, b *fr.Element) []*bn256.G1Affine {
	var (
		result []*bn256.G1Affine
		n      int64
	)
	n = int64(len(a))
	result = make([]*bn256.G1Affine, n)
	for i := int64(0); i < n; i++ {
		result[i] = zbn256.G1ScalarMult(a[i], b)
	}
	return result
}
