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
	"log"
	"math/big"
	"math/rand"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

type TransferSegment struct {
	// account index
	AccountIndex uint32 `json:"account_index"`
	// ElGamalEnc
	BalanceEnc *ElGamalEnc `json:"balance_enc"`
	// Balance
	Balance uint64 `json:"Balance"`
	// public key
	Pk *Point `json:"pk"`
	// bDelta
	BDelta int64 `json:"b_delta"`
	// secret key
	Sk *big.Int `json:"Sk"`
}

// TransferSegmentFormat Format is used to accept JSON string
type TransferSegmentFormat struct {
	// account index
	AccountIndex int `json:"account_index"`
	// ElGamalEnc
	BalanceEnc string `json:"balance_enc"`
	// Balance
	Balance int64 `json:"Balance"`
	// public key
	Pk string `json:"pk"`
	// bDelta
	BDelta int64 `json:"b_delta"`
	// secret key
	Sk string `json:"Sk"`
}

func FromTransferSegmentJSON(segmentStr string) ([]*TransferSegment, string) {
	var segmentFormats []*TransferSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormats)
	if err != nil {
		log.Println("[FromTransferSegmentJSON] err info:", err)
		return nil, ErrUnmarshal
	}
	if len(segmentFormats) < 2 {
		log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
		return nil, ErrInvalidTransferParams
	}
	skCount := 0
	var segments []*TransferSegment
	var indexExist = make(map[uint32]bool)
	rand.Shuffle(len(segmentFormats), func(i, j int) {
		segmentFormats[i], segmentFormats[j] = segmentFormats[j], segmentFormats[i]
	})
	for _, segmentFormat := range segmentFormats {
		if segmentFormat.BalanceEnc == "" || segmentFormat.Pk == "" {
			log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
			return nil, ErrInvalidTransferParams
		}
		// verify params
		if segmentFormat.AccountIndex < 0 || segmentFormat.Balance < 0 {
			log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
			return nil, ErrInvalidTransferParams
		}
		// create a new segment
		segment := new(TransferSegment)
		// get account index
		accountIndex := uint32(segmentFormat.AccountIndex)
		// each account should be different
		if indexExist[accountIndex] == true {
			log.Println("[FromTransferSegmentJSON] err info:", ErrReplicatedAccounts)
			return nil, ErrReplicatedAccounts
		}
		indexExist[accountIndex] = true
		segment.AccountIndex = accountIndex
		// get ElGamalEnc
		encBalance, err := twistedElgamal.FromString(segmentFormat.BalanceEnc)
		if err != nil {
			log.Println("[FromTransferSegmentJSON] err info:", err)
			return nil, ErrParseEnc
		}
		// get pk
		pk, err := curve.FromString(segmentFormat.Pk)
		if err != nil {
			log.Println("[FromTransferSegmentJSON] err info:", err)
			return nil, ErrParsePoint
		}
		// get bDelta
		bDelta := segmentFormat.BDelta
		// set values into segment
		segment.BalanceEnc = encBalance
		segment.Pk = pk
		segment.BDelta = bDelta
		// check if exists Sk
		if segmentFormat.Sk != "" {
			// get Sk
			skCount++
			sk, b := new(big.Int).SetString(segmentFormat.Sk, 10)
			if !b {
				log.Println("[FromTransferSegmentJSON] err info:", err)
				return nil, ErrParseBigInt
			}
			segment.Sk = sk
			// get Balance
			balance := uint64(segmentFormat.Balance)
			segment.Balance = balance
		}
		segments = append(segments, segment)
	}
	if skCount != 1 {
		log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
		return nil, ErrInvalidTransferParams
	}
	return segments, Success
}

type TransferTxInfo struct {
	// token id
	AssetId uint32
	// account indexes
	AccountsIndex []uint32
	// fee
	GasFee uint64
	// transfer proof
	Proof string
}
