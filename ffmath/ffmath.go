package ffmath

import (
	"crypto/rand"
	"math/big"
)

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

func Div(a, b *big.Int) *big.Int {
	return new(big.Int).Div(a, b)
}

func DivMod(a, b, modulo *big.Int) *big.Int {
	c := new(big.Int).Div(a, b)
	return new(big.Int).Mod(c, modulo)
}

func ModInverse(base *big.Int, modulo *big.Int) *big.Int {
	return new(big.Int).ModInverse(base, modulo)
}

func RandomValue(Order *big.Int) (r *big.Int, err error) {
	return rand.Int(rand.Reader, Order)
}
