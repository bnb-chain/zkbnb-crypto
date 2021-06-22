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

const (
	N   = 32 // max bits
	Max = 4294967296
)

var (
	G            = curve.G
	H            = curve.H
	Order        = curve.Order
	Zero         = big.NewInt(0)
	PadSecret    = big.NewInt(0)
	PadGammas, _ = new(big.Int).SetString("2029490050459469381010394860546295858668907545094365921480173886327233296650", 10)
	PadV         = curve.ScalarMul(G, PadGammas)
)
