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

package zecrey

import (
	"encoding/json"
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
	"math/rand"
	"time"
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

func FromTransferSegmentJSON(segmentStr string) (segmentsStr string, err error) {
	var segmentFormats []*TransferSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormats)
	if err != nil {
		log.Println("[FromTransferSegmentJSON] err info:", err)
		return "", err
	}
	if len(segmentFormats) < 2 {
		log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
		return "", errors.New("[FromTransferSegmentJSON] invalid transfer params")
	}
	skCount := 0
	var indexExist = make(map[uint32]bool)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(segmentFormats), func(i, j int) {
		segmentFormats[i], segmentFormats[j] = segmentFormats[j], segmentFormats[i]
	})
	var segments []*TransferSegment
	for _, segmentFormat := range segmentFormats {
		if segmentFormat.BalanceEnc == "" || segmentFormat.Pk == "" {
			log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
			return "", errors.New("[FromTransferSegmentJSON] invalid params")
		}
		// verify params
		if segmentFormat.AccountIndex < 0 || segmentFormat.Balance < 0 {
			log.Println("[FromTransferSegmentJSON] err info:", ErrInvalidTransferParams)
			return "", errors.New("[FromTransferSegmentJSON] invalid params")
		}
		// create a new segment
		segment := new(TransferSegment)
		// get account index
		accountIndex := uint32(segmentFormat.AccountIndex)
		// each account should be different
		if indexExist[accountIndex] == true {
			log.Println("[FromTransferSegmentJSON] err info:", ErrReplicatedAccounts)
			return "", errors.New("[FromTransferSegmentJSON] " + ErrReplicatedAccounts)
		}
		indexExist[accountIndex] = true
		segment.AccountIndex = accountIndex
		// get ElGamalEnc
		encBalance, err := twistedElgamal.FromString(segmentFormat.BalanceEnc)
		if err != nil {
			log.Println("[FromTransferSegmentJSON] err info:", err)
			return "", err
		}
		// get pk
		pk, err := curve.FromString(segmentFormat.Pk)
		if err != nil {
			log.Println("[FromTransferSegmentJSON] err info:", err)
			return "", err
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
				return "", err
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
		return "", errors.New("[FromTransferSegmentJSON] invalid params")
	}
	segmentsBytes, err := json.Marshal(segments)
	if err != nil {
		return "", err
	}
	return string(segmentsBytes), nil
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
	// memo
	Memo string
}
