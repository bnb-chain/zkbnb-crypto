package ffmath

import (
	"github.com/consensys/gurvy/bn256/fr"
	"math/big"
)

func Add(x *fr.Element, y *fr.Element) *fr.Element {
	return new(fr.Element).Add(x, y)
}

func Sub(x *fr.Element, y *fr.Element) *fr.Element {
	return new(fr.Element).Sub(x, y)
}

func Multiply(factor1 *fr.Element, factor2 *fr.Element) *fr.Element {
	return new(fr.Element).Mul(factor1, factor2)
}

func Div(a, b *fr.Element) *fr.Element {
	return new(fr.Element).Div(a, b)
}

func Inverse(base *fr.Element) *fr.Element {
	return new(fr.Element).Inverse(base)
}

func ToBigInt(z *fr.Element) *big.Int {
	zInt := new(big.Int)
	return z.ToBigIntRegular(zInt)
}

func FromBigInt(z *big.Int) *fr.Element {
	return new(fr.Element).SetBigInt(z)
}
