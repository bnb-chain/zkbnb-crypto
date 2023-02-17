/*
 * Copyright © 2022 ZkBNB Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package txtypes

import (
	"bytes"
	"encoding/hex"
	"errors"
	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbnb-crypto/ffmath"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/ethereum/go-ethereum/common"

	"github.com/bnb-chain/zkbnb-crypto/util"
)

func WriteInt64IntoBuf(buf *bytes.Buffer, inputs ...int64) {
	if len(inputs) == 0 {
		log.Fatalln("[WriteInt64IntoBuf] no input")
	}
	if len(inputs) > 4 {
		log.Fatalln("[WriteInt64IntoBuf] too many inputs")
	}
	// The variable of bn254 curve is less than 2^254, avoid overflow here.
	if len(inputs) == 4 && inputs[0] >= 2^62 {
		log.Fatalln("[WriteInt64IntoBuf] inputs overflow")
	}

	packedValue := new(big.Int).SetInt64(inputs[0])
	for _, input := range inputs[1:] {
		packedValue = new(big.Int).Mul(packedValue, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil))
		packedValue = new(big.Int).Add(packedValue, big.NewInt(input))
	}
	buf.Write(packedValue.FillBytes(make([]byte, 32)))
}

func WriteBigIntIntoBuf(buf *bytes.Buffer, a *big.Int) {
	buf.Write(a.FillBytes(make([]byte, 32)))
}

func StringToBigInt(a string) (res *big.Int, err error) {
	if a == "" {
		return big.NewInt(0), nil
	}
	res, isValid := new(big.Int).SetString(a, 10)
	if !isValid {
		log.Println("[StringToBigInt] invalid string to big int")
		return nil, errors.New("[StringToBigInt] invalid string to big int")
	}
	return res, nil
}

func PaddingStringToBytes32(name string) []byte {
	buf := make([]byte, 32)
	copy(buf, name)
	return buf
}

func PaddingAddressToBytes32(addr string) []byte {
	return new(big.Int).SetBytes(common.FromHex(addr)).FillBytes(make([]byte, 32))
}

/*
ToPackedAmount: convert big int to 40 bit, 5 bits for 10^x, 35 bits for a * 10^x
*/
func ToPackedAmount(amount *big.Int) (res int64, err error) {
	return util.ToPackedAmount(amount)
}

func CleanPackedAmount(amount *big.Int) (nAmount *big.Int, err error) {
	return util.CleanPackedAmount(amount)
}

/*
ToPackedFee: convert big int to 16 bit, 5 bits for 10^x, 11 bits for a * 10^x
*/
func ToPackedFee(amount *big.Int) (res int64, err error) {
	return util.ToPackedFee(amount)
}

func CleanPackedFee(amount *big.Int) (nAmount *big.Int, err error) {
	return util.CleanPackedFee(amount)
}

func FromHex(s string) ([]byte, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}

	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func IsValidHashBytes(bytes []byte) bool {
	if len(bytes) != HashLength {
		return false
	}

	return !isZeroByteSlice(bytes)
}

func IsValidHash(hash string) bool {
	hashBytes, err := FromHex(hash)
	if err != nil {
		return false
	}
	if len(hashBytes) != HashLength {
		return false
	}

	return !isZeroByteSlice(hashBytes)
}

func isZeroByteSlice(bytes []byte) bool {
	for _, s := range bytes {
		if s != 0 {
			return false
		}
	}
	return true
}

func IsValidL1Address(address string) bool {
	return common.IsHexAddress(address)
}

func ParsePublicKey(pkStr string) (pk *eddsa.PublicKey, err error) {
	pkBytes, err := hex.DecodeString(pkStr)
	if err != nil {
		return nil, err
	}
	pk = new(eddsa.PublicKey)
	size, err := pk.SetBytes(pkBytes)
	if err != nil {
		return nil, err
	}
	if size != 32 {
		return nil, errors.New("invalid public key")
	}
	return pk, nil
}

type PoseidonVariable interface{}

func FromBigIntToFr(b *big.Int) *fr.Element {
	ele := fr.Element{0, 0, 0, 0}
	ele.SetBigInt(b)
	return &ele
}

func FromHexStrToFr(s string) (*fr.Element, error) {
	n, success := new(big.Int).SetString(s, 16)
	if !success {
		return nil, errors.New("not a valid hex str")
	}
	return FromBigIntToFr(n), nil
}

func FromBytesToFr(b []byte) (*fr.Element, error) {
	n := new(big.Int).SetBytes(b)
	return FromBigIntToFr(n), nil
}

func Poseidon(variables ...PoseidonVariable) []byte {
	frArrays := make([]*fr.Element, len(variables))
	for i, v := range variables {
		if vi, ok := v.(int64); ok {
			frArrays[i] = FromBigIntToFr(new(big.Int).SetInt64(vi))
		}

		if vi, ok := v.(int); ok {
			frArrays[i] = FromBigIntToFr(new(big.Int).SetInt64(int64(vi)))
		}

		if vi, ok := v.(string); ok {
			frArrays[i] = FromBigIntToFr(new(big.Int).SetBytes(ffmath.Mod(new(big.Int).SetBytes(common.FromHex(vi)), curve.Modulus).FillBytes(make([]byte, 32))))
		}

		if vi, ok := v.([]byte); ok {
			frArrays[i] = FromBigIntToFr(new(big.Int).SetBytes(ffmath.Mod(new(big.Int).SetBytes(vi), curve.Modulus).FillBytes(make([]byte, 32))))
		}

		if vi, ok := v.(*big.Int); ok {
			frArrays[i] = FromBigIntToFr(vi)
		}
	}

	poseidonHashBytes := poseidon.Poseidon(frArrays...).Bytes()
	return poseidonHashBytes[:]
}
