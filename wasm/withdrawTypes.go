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

package wasm

import (
	"encoding/json"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	WithdrawSegment: which is used to construct withdraw proof
*/
type WithdrawSegment struct {
	EncVal *ElGamalEnc `json:"enc_val"`
	Pk     *Point      `json:"pk"`
	BStar  *big.Int    `json:"b_star"`
	Sk     *big.Int    `json:"sk"`
}

/*
	WithdrawSegmentFormat: format version of WithdrawSegment
*/
type WithdrawSegmentFormat struct {
	EncVal string `json:"enc_val"`
	Pk     string `json:"pk"`
	BStar  int    `json:"b_star"`
	Sk     string `json:"sk"`
}

func FromWithdrawSegmentJSON(segmentStr string) (*WithdrawSegment, string) {
	var withdrawSegmentFormat *WithdrawSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &withdrawSegmentFormat)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if withdrawSegmentFormat.EncVal == "" || withdrawSegmentFormat.Pk == "" ||
		withdrawSegmentFormat.BStar >= 0 || withdrawSegmentFormat.Sk == "" {
		return nil, ErrInvalidWithdrawParams
	}
	encVal, err := twistedElgamal.FromString(withdrawSegmentFormat.EncVal)
	if err != nil {
		return nil, ErrParseEnc
	}
	pk, err := curve.FromString(withdrawSegmentFormat.Pk)
	if err != nil {
		return nil, ErrParsePoint
	}
	bStar := big.NewInt(int64(withdrawSegmentFormat.BStar))
	sk, b := new(big.Int).SetString(withdrawSegmentFormat.Sk, 10)
	if !b {
		return nil, ErrParseBigInt
	}
	withdrawSegment := &WithdrawSegment{
		EncVal: encVal,
		Pk:     pk,
		BStar:  bStar,
		Sk:     sk,
	}
	return withdrawSegment, Success
}

type WithdrawTransactionAo struct {
	// token id
	TokenId uint32
	// L2 address
	L2Address string
	// L1 address
	L1Address string
	// withdraw amount
	Amount uint32
	// withdraw proof
	Proof *zecrey.WithdrawProof
	// create time
	CreateAt int64
}
