package abi

import (
	"github.com/consensys/gnark/frontend"
)

func WrapToAbiString(wrap string, wraplen int) []frontend.Variable {

	bs := []byte(wrap)
	if len(bs) > wraplen {
		panic("can not exceed the limit of wrap len")
	}

	ret := make([]frontend.Variable, wraplen)
	for i := range ret {
		ret[i] = AbiEncodeEmptyByte
	}

	for i := range bs {
		ret[len(ret)+i-len(bs)] = bs[i]
	}

	return ret
}

func WrapToAbiBytes32(target [32]byte) []frontend.Variable {
	ret := make([]frontend.Variable, 32)
	for i := range ret {
		ret[i] = target[i]
	}
	return ret
}

func WrapToAbiBytes20(target [20]byte) []frontend.Variable {
	ret := make([]frontend.Variable, 20)
	for i := range ret {
		ret[i] = target[i]
	}
	return ret
}

func WrapToAbiBytes16(target [16]byte) []frontend.Variable {
	ret := make([]frontend.Variable, 16)
	for i := range ret {
		ret[i] = target[i]
	}
	return ret
}
