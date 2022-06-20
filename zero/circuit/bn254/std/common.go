package std

type CommonPkProof struct {
	Pk_u              Point
	A_pk_u            Point
	Z_sk_u, Z_sk_uInv Variable
}

func SelectCommonPkProof(api API, flag Variable, a, b CommonPkProof) (res CommonPkProof) {
	res.Pk_u = SelectPoint(api, flag, a.Pk_u, b.Pk_u)
	res.A_pk_u = SelectPoint(api, flag, a.A_pk_u, b.A_pk_u)
	res.Z_sk_u = api.Select(flag, a.Z_sk_u, b.Z_sk_u)
	res.Z_sk_uInv = api.Select(flag, a.Z_sk_uInv, b.Z_sk_uInv)
	return res
}

type CommonTProof struct {
	C_PrimeNeg      ElGamalEncConstraints
	A_T_C_RPrimeInv Point
	Z_bar_r         Variable
	T               Point
}

func SelectCommonTProof(api API, flag Variable, a, b CommonTProof) (res CommonTProof) {
	res.C_PrimeNeg = SelectElgamal(api, flag, a.C_PrimeNeg, b.C_PrimeNeg)
	res.A_T_C_RPrimeInv = SelectPoint(api, flag, a.A_T_C_RPrimeInv, b.A_T_C_RPrimeInv)
	res.Z_bar_r = api.Select(flag, a.Z_bar_r, b.Z_bar_r)
	res.T = SelectPoint(api, flag, a.T, b.T)
	return res
}

func SetPkProof(pk Point, A_pk Point, Z_sk, Z_skInv Variable) (proof CommonPkProof) {
	proof.Pk_u = pk
	proof.A_pk_u = A_pk
	proof.Z_sk_u = Z_sk
	proof.Z_sk_uInv = Z_skInv
	return proof
}

func SetTProof(C_PrimeNeg ElGamalEncConstraints, A_T_C_RPrimeInv Point, Z_bar_r Variable, T Point) (proof CommonTProof) {
	proof.C_PrimeNeg = C_PrimeNeg
	proof.A_T_C_RPrimeInv = A_T_C_RPrimeInv
	proof.Z_bar_r = Z_bar_r
	proof.T = T
	return proof
}
