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

package zecrey_legend

import (
	"bytes"
	"errors"
	"log"
	"math/big"
)

func writeUint64IntoBuf(buf *bytes.Buffer, a uint64) {
	buf.Write(new(big.Int).SetUint64(a).FillBytes(make([]byte, 32)))
}

func writeInt64IntoBuf(buf *bytes.Buffer, a int64) {
	buf.Write(new(big.Int).SetInt64(a).FillBytes(make([]byte, 32)))
}

func writeBigIntIntoBuf(buf *bytes.Buffer, a *big.Int) {
	buf.Write(a.FillBytes(make([]byte, 32)))
}

func StringToBigInt(a string) (res *big.Int, err error) {
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
