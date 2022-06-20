package mockAccount

import (
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"math/big"
)

var (
	PoolIndex             = uint32(0)
	PoolName              = "pool.zecrey-legend"
	PoolSk, _             = new(big.Int).SetString("14920211685767618838764344529549360512929912103991001716704990292355229543", 10)
	PoolPk, _             = curve.FromString("Qj7JKBoBeYviSGgH+owFRaRC9i5ZFiqCwnzqDBsCVg4=")
	PoolLiquidityABalance = uint64(40000)
	PoolLiquidityAR, _    = new(big.Int).SetString("819119503963334694170948179618957634294931441341740602949730017879165356511", 10)
	PoolLiquidityBBalance = uint64(40000)
	PoolLiquidityBR, _    = new(big.Int).SetString("1335632665585068233764489615674686827129495579699351243398933045781110935836", 10)
)
