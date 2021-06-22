package wasm

import (
	"zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

type (
	Point      = tebn254.Point
	ElGamalEnc = twistedElgamal.ElGamalEnc
)

