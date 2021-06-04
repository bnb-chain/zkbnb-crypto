package zmimc

import "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

const SEED = "ZecreyMIMCSeed"

var (
	Hmimc = mimc.NewMiMC(SEED)
)
