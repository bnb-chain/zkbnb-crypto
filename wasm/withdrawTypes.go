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
	EncBalance *ElGamalEnc `json:"enc_balance"`
	Pk         *Point      `json:"pk"`
	Balance    *big.Int    `json:"balance"`
	BStar      *big.Int    `json:"b_star"`
	Sk         *big.Int    `json:"sk"`
	Fee        *big.Int    `json:"fee"`
}

/*
	WithdrawSegmentFormat: format version of WithdrawSegment
*/
type WithdrawSegmentFormat struct {
	EncBalance string `json:"enc_balance"`
	Balance    int    `json:"balance"`
	Pk         string `json:"pk"`
	BStar      int    `json:"b_star"`
	Sk         string `json:"sk"`
	Fee        int    `json:"fee"`
}

func FromWithdrawSegmentJSON(segmentStr string) (*WithdrawSegment, string) {
	var withdrawSegmentFormat *WithdrawSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &withdrawSegmentFormat)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if withdrawSegmentFormat.EncBalance == "" || withdrawSegmentFormat.Pk == "" ||
		withdrawSegmentFormat.BStar < 0 || withdrawSegmentFormat.Sk == "" {
		return nil, ErrInvalidWithdrawParams
	}
	encBalance, err := twistedElgamal.FromString(withdrawSegmentFormat.EncBalance)
	if err != nil {
		return nil, ErrParseEnc
	}
	balance := big.NewInt(int64(withdrawSegmentFormat.Balance))
	pk, err := curve.FromString(withdrawSegmentFormat.Pk)
	if err != nil {
		return nil, ErrParsePoint
	}
	bStar := big.NewInt(int64(withdrawSegmentFormat.BStar))
	sk, b := new(big.Int).SetString(withdrawSegmentFormat.Sk, 10)
	if !b {
		return nil, ErrParseBigInt
	}
	fee := big.NewInt(int64(withdrawSegmentFormat.Fee))
	withdrawSegment := &WithdrawSegment{
		EncBalance: encBalance,
		Balance:    balance,
		Pk:         pk,
		BStar:      bStar,
		Sk:         sk,
		Fee:        fee,
	}
	return withdrawSegment, Success
}

type WithdrawTransactionAo struct {
	// token id
	TokenId uint32
	// zecrey index
	AccountIndex uint32
	// L1 address
	L1Address string
	// withdraw amount
	Amount uint32
	// withdraw fee
	Fee uint32
	// withdraw proof
	Proof *zecrey.WithdrawProof
	// create time
	CreateAt int64
}
