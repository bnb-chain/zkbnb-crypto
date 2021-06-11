package commitRange

import "math/big"

type ComRangeProof struct {
	// binary proof
	Cas, Cbs     []*Point
	Fs, Zas, Zbs []*big.Int
	// same commitment proof
	Zb, Zr, Zrprime *big.Int
	A_T, A_Tprime   *Point
	// public statements
	T, Tprime, G, H *Point
	As              []*Point
}
