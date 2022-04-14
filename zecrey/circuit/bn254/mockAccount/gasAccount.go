package mockAccount

import (
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"math/big"
)

var (
	GasIndex         = uint32(2)
	GasName          = "gas.zecrey"
	GasSk, _         = new(big.Int).SetString("389992331087627035440267920964763609290946838805756116258006273558956629436", 10)
	GasPk, _         = curve.FromString("pdil66Onf37BlB68K2eqwafGBd1GS12w6Zm6OfG1mAQ=")
	GasAssetABalance = uint64(100)
	GasCA, _         = twistedElgamal.FromString("7jOd/tOJccTcwhsoXJa+L4hSDPiZJ+EbPot0xA+0fJ6tTCzY2bF5GnpXyljqhSYrzoT1e/yg2sqy8bHiOCNFmg==")
	GasAssetBBalance = uint64(200)
	GasCB, _         = twistedElgamal.FromString("+QMqVvgvjz4dZla99qrO1T+lqqzA5J5A0x88L7zaARqvZhIjDGemrMyGifkWV1Ucv3a8YcBdjypG7ImdCzumkA==")
	GasAssetCBalance = uint64(300)
	GasCC, _         = twistedElgamal.FromString("Va/BK5Ndas4bB3pSH/YOvVLBiPUZ/RV7S+rWdrREBw+4dVoG9Duprqf7EhjnlWCnTiRfLcZlYYQK+H4w2ijFrA==")
	GasAssetDBalance = uint64(400)
	GasCD, _         = twistedElgamal.FromString("hFE5iZ44pISnvce1S78BVTvWZpL6y2eYwI9gwNwDOCRYqO8Lj/zn7x6J85dPJcS/8bpsXL/cPS2rYNt709YjJg==")
)
