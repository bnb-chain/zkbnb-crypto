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
	"errors"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
)

// L1PTransferDepositSegmentFormat Format is used to accept JSON string
type L1PTransferDepositSegmentFormat struct {
	// Private key
	Sk string `json:"sk"`
	// chain id
	ChainId int `json:"chain_id"`
	// nonce
	Nonce int `json:"nonce"`
	// contract address
	ContractAddress string `json:"contract_address"`
	// asset id
	AssetId int `json:"asset_id"`
	// zecrey addr
	ZecreyAccount string `json:"zecrey_account"`
	// amount
	Amount string `json:"amount"`
	// gas price
	GasPrice string `json:"gas_price"`
	// gas limit
	GasLimit int `json:"gas_limit"`
}

func FromL1PTransferSegmentJSON(segmentStr string, senderDelta *big.Int) ([]*PTransferSegment, string) {
	var transferSegmentFormats []*PTransferSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &transferSegmentFormats)
	if err != nil {
		return nil, err.Error()
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
			return nil, err.Error()
		}
		// get pk
		pk, err := curve.FromString(segmentFormat.Pk)
		if err != nil {
			return nil, err.Error()
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
			// check if sender amount is correct
			if ffmath.Add(senderDelta, segment.BDelta).Cmp(big.NewInt(0)) != 0 {
				return nil, errors.New("err: inconsistent sender delta and amount").Error()
			}
			// reset balance
			delta := &twistedElgamal.ElGamalEnc{
				CL: curve.ZeroPoint(),
				CR: curve.ScalarMul(curve.H, senderDelta),
			}
			segment.EncBalance, err = twistedElgamal.EncAdd(segment.EncBalance, delta)
			if err != nil {
				return nil, err.Error()
			}
			// get balance
			balance := ffmath.Add(big.NewInt(int64(segmentFormat.Balance)), senderDelta)
			segment.Balance = balance
		}
		segments = append(segments, segment)
	}
	if skCount != 1 {
		return nil, ErrInvalidTransferParams
	}
	return segments, Success
}

type L1PrivacyTransferTxInfo struct {
	ChainId       uint8
	AssetId       uint32
	Fee           uint32
	AccountIndex  uint32
	DepositAmount uint32
	DepositTxHash string
	TransferTx    *TransferTxInfo
	// withdraw to address
	WithdrawTo string
}
