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
)

type PTransferSegment struct {
	// ElGamalEnc
	EncBalance *ElGamalEnc `json:"enc_balance"`
	// balance
	Balance *big.Int `json:"balance"`
	// public key
	Pk *Point `json:"pk"`
	// bDelta
	BDelta *big.Int `json:"b_delta"`
	// secret key
	Sk *big.Int `json:"sk"`
}

// PTransferSegmentFormat Format is used to accept JSON string
type PTransferSegmentFormat struct {
	// ElGamalEnc
	EncBalance string `json:"enc_balance"`
	// balance
	Balance int `json:"balance"`
	// public key
	Pk string `json:"pk"`
	// bDelta
	BDelta int `json:"b_delta"`
	// secret key
	Sk string `json:"sk"`
}

func FromPTransferSegmentJSON(segmentStr string) ([]*PTransferSegment, string) {
	var transferSegmentFormats []*PTransferSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &transferSegmentFormats)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if len(transferSegmentFormats) < 2 {
		return nil, ErrInvalidTransferParams
	}
	skCount := 0
	var segments []*PTransferSegment
	for _, segmentFormat := range transferSegmentFormats {
		if segmentFormat.EncBalance == "" || segmentFormat.Pk == "" {
			return nil, ErrInvalidTransferParams
		}
		// create a new segment
		segment := new(PTransferSegment)
		// get ElGamalEnc
		encBalance, err := twistedElgamal.FromString(segmentFormat.EncBalance)
		if err != nil {
			return nil, ErrParseEnc
		}
		// get pk
		pk, err := curve.FromString(segmentFormat.Pk)
		if err != nil {
			return nil, ErrParsePoint
		}
		// get bDelta
		bDelta := big.NewInt(int64(segmentFormat.BDelta))
		// set values into segment
		segment.EncBalance = encBalance
		segment.Pk = pk
		segment.BDelta = bDelta
		// check if exists sk
		if segmentFormat.Sk != "" {
			// get sk
			skCount++
			sk, b := new(big.Int).SetString(segmentFormat.Sk, 10)
			if !b {
				return nil, ErrParseBigInt
			}
			segment.Sk = sk
			// get balance
			balance := big.NewInt(int64(segmentFormat.Balance))
			segment.Balance = balance
		}
		segments = append(segments, segment)
	}
	if skCount != 1 {
		return nil, ErrInvalidTransferParams
	}
	return segments, Success
}

type TransferTransactionAo struct {
	// token id
	TokenId uint32
	// account indexes
	AccountsIndex []int
	// fee
	Fee uint32
	// transfer proof
	Proof string
	// create time
	CreateAt int64
}
