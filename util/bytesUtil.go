package util

import (
	"errors"
	"math/big"
)

// contact bytes
func ContactBytes(a, b []byte, in ...[]byte) (res []byte) {
	contact := func(_a, _b []byte) (_res []byte) {
		_res = append(_a, _b...)
		return _res
	}
	res = append(a, b...)
	for i := 0; i < len(in); i++ {
		res = contact(res, in[i])
	}
	return res
}

func FlipBytes(bytesIn []byte) []byte {
	length := len(bytesIn)
	flippedBytes := make([]byte, length)
	for i := 0; i < length; i++ {
		flippedBytes[i] = bytesIn[i] ^ 255
	}
	return flippedBytes
}

func ToByteArray(in *big.Int) []byte {
	isNegative := in.Cmp(new(big.Int).SetInt64(0)) < 0
	bytes := in.Bytes()
	length := len(bytes)
	if length == 0 {
		return []byte{0}
	}
	highestByte := bytes[0]
	var convertedBytes []byte
	if !isNegative {
		if (highestByte & 128) != 0 {

			convertedBytes = make([]byte, length+1)
			convertedBytes[0] = 0
			copy(convertedBytes[1:], bytes)
			return convertedBytes
		} else {
			return bytes
		}
	} else {
		if (highestByte & 128) != 0 {

			convertedBytes = make([]byte, length+1)
			convertedBytes[0] = 255
			copy(convertedBytes[1:], FlipBytes(bytes))
		} else {
			convertedBytes = FlipBytes(bytes)
		}

		convertedInt := new(big.Int).SetBytes(convertedBytes)
		convertedInt.Add(convertedInt, big.NewInt(1))
		return convertedInt.Bytes()
	}
}

func FromByteArray(bytesIn []byte) (*big.Int, error) {
	const MINUS_ONE = -1
	if len(bytesIn) == 0 {
		err := errors.New("cannot convert empty array to big.Int")
		return nil, err
	}
	highestByte := bytesIn[0]
	isNegative := (highestByte & 128) != 0
	var convertedBytes []byte
	if isNegative {
		tmpInt := new(big.Int).SetBytes(bytesIn)
		tmpInt = tmpInt.Sub(tmpInt, big.NewInt(1))
		tmpBytes := tmpInt.Bytes()
		if tmpBytes[0] == 255 {
			convertedBytes = FlipBytes(tmpBytes)[1:]
		} else {
			convertedBytes = tmpBytes
			copy(convertedBytes, FlipBytes(tmpBytes))
		}
		tmp := new(big.Int).SetBytes(convertedBytes)
		return tmp.Mul(tmp, big.NewInt(MINUS_ONE)), nil
	} else {
		// if positive leave unchanged (additional 0-bytes will be ignored)
		return new(big.Int).SetBytes(bytesIn), nil
	}
}
