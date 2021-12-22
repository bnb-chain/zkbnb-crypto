package mockAccount

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

var (
	TreasuryIndex         = uint32(1)
	TreasuryName          = "treasury.zecrey"
	TreasurySk, _         = new(big.Int).SetString("2698126873495378862712283557894415700665308711050547649798144006601306535070", 10)
	TreasuryPk, _         = curve.FromString("LvLgPxleUCIeU4ZzHA8v2+3jWj3DILnP1eOw3/8B3iA=")
	TreasuryAssetABalance = uint64(100)
	TreasuryCA, _         = twistedElgamal.FromString("MWYT5uW+eLjZc3Gt17JMBa95tU4qTpZC89aXEaEykagj1aoNF4MVT2gcbrTZJjw7snW6HAcD9jro9sHtG5Lzpg==")
	TreasuryAssetBBalance = uint64(200)
	TreasuryCB, _         = twistedElgamal.FromString("p2TRrBbjAMN4K6G95HhAhpeVuTtnLWd2R6yzENQtcxHHzax7fdEzVaJdfoCPNv4xse9KTa3C858ZlbkrPCiLIw==")
	TreasuryAssetCBalance = uint64(300)
	TreasuryCC, _         = twistedElgamal.FromString("cx0+79TuUvf0idFQq0I7kPO3tt3wMMLyfgQLEpVq/CiwHY4yrukjJk6Kcaz16+WYPT1yQcyd77DVgd4MFA1ACw==")
	TreasuryAssetDBalance = uint64(400)
	TreasuryCD, _         = twistedElgamal.FromString("Ksz0WQtkQ2kJlZrSuViArWAv2zedTlV7KVxocLx0B56SIP/iUsHqYlQqHip3LYNOiAK1lW5LfitHlLmiwzuhBw==")
)
