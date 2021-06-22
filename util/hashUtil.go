package util

import (
	"bytes"
	"hash"
	"math/big"
)

/*
Hash is responsible for the computing a Zp element given the input string.
*/
func HashToInt(b bytes.Buffer, h hash.Hash) (*big.Int, error) {
	h.Reset()
	digest := h
	digest.Write(b.Bytes())
	output := digest.Sum(nil)
	tmp := output[0:]
	return FromByteArray(tmp)
}
