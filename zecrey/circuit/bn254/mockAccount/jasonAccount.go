package mockAccount

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

var (
	JasonIndex         = uint32(5)
	JasonName          = "jason.zecrey"
	JasonSk, _         = new(big.Int).SetString("1212515942558314278513678451807728016147025009624690004795762586901554004071", 10)
	JasonPk, _         = curve.FromString("XxTFgJ0ckxApWHLtIGG/FAtiQ93osbuvlfcJWrN2mQU=")
	JasonAssetABalance = uint64(1000)
	JasonCA, _         = twistedElgamal.FromString("J/HNmfvSFLYe76PTlLs6DHzKLUCusWz/5JsUC6ph/wgRbC0p+IS+FGk1uppBY99NHE5VXtyU+yMarwVmBc0JEw==")
	JasonAssetBBalance = uint64(2000)
	JasonCB, _         = twistedElgamal.FromString("aMZUOfop2AgyNXXpD7w+8bhX80qc+w8QoZZmCQ0A2p6L6a0zlfYP2XLsck/05DqxReEWoYQ0B3sDpRWiEcngmQ==")
	JasonAssetCBalance = uint64(3000)
	JasonCC, _         = twistedElgamal.FromString("rFG1KKPSirBxRqK83VwYBeGF8ydBerOueuqsesvkToVR5aijn+cxUzkmX0MarAbKifMd9O6aT14T0ezA0aosHg==")
	JasonAssetDBalance = uint64(4000)
	JasonCD, _         = twistedElgamal.FromString("zr+EHBmyz3zbCGZbIMWRsfiWThq6m/S5IGZRBRZPQSmTaSL/D2m9190xKRBK3BCkJVVXSOoiaV+OnvLgST5XHw==")
	JasonLpBalance     = uint64(10)
	JasonCLp, _        = twistedElgamal.FromString("CJTiOJwEK1PHthpr8b935RvLtEyTNWyyyI2Ym67cgIxY8BvGK2thBi47NguDqUnVpZZPx5Ll4GnLxQBJdl5TKA==")
)
