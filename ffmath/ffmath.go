package ffmath

import (
	"crypto/rand"
	"math/big"
)

/**
 * Returns base**exponent mod |modulo| also works for negative exponent (contrary to big.Int.Exp)
 */
func ModPow(base *big.Int, exponent *big.Int, modulo *big.Int) *big.Int {

	var returnValue *big.Int

	if exponent.Cmp(big.NewInt(0)) >= 0 {
		returnValue = new(big.Int).Exp(base, exponent, modulo)
	} else {
		// Exp doesn't support negative exponent so instead:
		// use positive exponent than take inverse (modulo)..
		returnValue = ModInverse(new(big.Int).Exp(base, new(big.Int).Abs(exponent), modulo), modulo)
	}
	return returnValue
}

func Add(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Add(x, y)
}

func AddMod(x, y *big.Int, ORDER *big.Int) *big.Int {
	res := Add(x, y)
	res = Mod(res, ORDER)
	return res
}

func Sub(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}

func SubMod(x, y *big.Int, ORDER *big.Int) *big.Int {
	res := Sub(x, y)
	res = Mod(res, ORDER)
	return res
}

func Mod(base *big.Int, modulo *big.Int) *big.Int {
	return new(big.Int).Mod(base, modulo)
}

func Multiply(factor1 *big.Int, factor2 *big.Int) *big.Int {
	return new(big.Int).Mul(factor1, factor2)
}

func MultiplyMod(factor1 *big.Int, factor2 *big.Int, ORDER *big.Int) *big.Int {
	res := Multiply(factor1, factor2)
	res = Mod(res, ORDER)
	return res
}

func ModInverse(base *big.Int, modulo *big.Int) *big.Int {
	return new(big.Int).ModInverse(base, modulo)
}

func RandomValue(Order *big.Int) *big.Int {
	r, _ := rand.Int(rand.Reader, Order)
	return r
}
