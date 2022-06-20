package mockAccount

import (
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"math/big"
)

var (
	GavinIndex         = uint32(4)
	GavinName          = "gavin.zecrey-legend"
	GavinSk, _         = new(big.Int).SetString("2715501719737389726909271559236769082041033466084720448102229307207566255757", 10)
	GavinPk, _         = curve.FromString("Y1M+SobGyZKJMOvIfm8c9qlzlRNDYVU2b+N4xCG0tKw=")
	GavinAssetABalance = uint64(1000)
	GavinCA, _         = twistedElgamal.FromString("fSp/f+2ggcourkrxd0YtPm+Le8NWyascpOl+tY16uJtEOooQrm64DryUb/84V9ARhBKHQ/epRnG6acyetrenmQ==")
	GavinAssetBBalance = uint64(2000)
	GavinCB, _         = twistedElgamal.FromString("4h9WQOnGagHvPxLQnbnCVRKp+c+NlBDmU5LTtleLVIcoa0aPYgyed/2EaHnAqENONmsGao1f7oETrnCu6fg2EA==")
	GavinAssetCBalance = uint64(3000)
	GavinCC, _         = twistedElgamal.FromString("HkYNOkhGD1CgnkekVHOfCfuNKrva053MEEk2Lyi6YSyG1y3xEE26YcLhqZCgUi7YrIKZdxWVvEkd3pRLDejWIA==")
	GavinAssetDBalance = uint64(4000)
	GavinCD, _         = twistedElgamal.FromString("iYdEKPj7ihNDtfwJIwZdULxgeYje5dM1OVjsLCYh1xRYs3rHvNfvEdhgWrG1ZhFyJU611Eo7eYwHxikyBk1IAg==")
	GavinLpBalance     = uint64(10)
	GavinCLp, _        = twistedElgamal.FromString("lyRHo4kTztmQBMhdiIVU43f0av0ulesMV7hBotOy6I+fEmdtBp6jPs2sbeNrCKbv5Y/1ng0XAhxxMMLyZs9+gA==")
)
