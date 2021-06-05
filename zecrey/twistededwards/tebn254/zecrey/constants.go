package zecrey

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/bulletProofs"
)

type (
	ElGamalEnc     = twistedElgamal.ElGamalEnc
	Point          = curve.Point
	BPSetupParams  = bulletProofs.BPSetupParams
	AggBulletProof = bulletProofs.AggBulletProof
)

var (
	G     = curve.G
	H     = curve.H
	Order = curve.Order
	Zero  = big.NewInt(0)
)
