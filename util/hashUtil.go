package util

import (
	"bytes"
	"hash"
	"math/big"
)

// Calculate hash value
func CalHash(m []byte, hFunction func() hash.Hash) ([]byte, error) {
	h := hFunction()
	_, err := h.Write(m)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

/*
Hash is responsible for the computing a Zp element given the input string.
*/
func HashToInt(b bytes.Buffer, hFunction func() hash.Hash) (*big.Int, error) {
	digest := hFunction()
	digest.Write(b.Bytes())
	output := digest.Sum(nil)
	tmp := output[0:]
	return FromByteArray(tmp)
}
