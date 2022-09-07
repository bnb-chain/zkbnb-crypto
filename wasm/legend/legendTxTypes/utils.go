/*
 * Copyright © 2021 Zecrey Protocol
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

package legendTxTypes

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/ethereum/go-ethereum/common"

	"github.com/bnb-chain/zkbas-crypto/util"
)

func WriteUint64IntoBuf(buf *bytes.Buffer, a uint64) {
	buf.Write(new(big.Int).SetUint64(a).FillBytes(make([]byte, 32)))
}

func WriteInt64IntoBuf(buf *bytes.Buffer, a int64) {
	buf.Write(new(big.Int).SetInt64(a).FillBytes(make([]byte, 32)))
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

func ConvertStringHexToBytes32(hexStr string) [32]byte {
	var hexBytes32 [32]byte
	hexBytes := common.FromHex(hexStr)
	copy(hexBytes32[:], hexBytes)
	return hexBytes32
}

func ConvertBytesToBytes32(bytes []byte) [32]byte {
	var hexBytes32 [32]byte
	copy(hexBytes32[:], bytes)
	return hexBytes32
}

func ConvertStringHexToBytes20(hexStr string) [20]byte {
	var hexBytes20 [20]byte
	hexBytes := common.FromHex(hexStr)
	copy(hexBytes20[:], hexBytes)
	return hexBytes20
}

func ConvertStringHexToBytes16(bi *big.Int) [16]byte {
	var hexBytes16 [16]byte
	copy(hexBytes16[:], bi.FillBytes(make([]byte, 32)))
	return hexBytes16
}
