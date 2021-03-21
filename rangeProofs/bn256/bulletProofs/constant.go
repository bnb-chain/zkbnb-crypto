package bp_bn128

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
)

var (
	ORDER = ffmath.FromBigInt(zbn256.ORDER)
	SEEDU = "ZKSneakBulletProofsSetupU"
	SEEDH = "ZKSneakBulletProofsSetupH"
)

const MAX_RANGE_END = 4294967296
