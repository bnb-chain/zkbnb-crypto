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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateTransferNftTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *TransferNftTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: -1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// ToAccountIndex
		{
			fmt.Errorf("ToAccountIndex should not be less than %d", minAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   -1,
			},
		},
		{
			fmt.Errorf("ToAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   maxAccountIndex + 1,
			},
		},
		// ToL1Address
		{
			fmt.Errorf("ToL1Address(%s) is invalid", "0000000000000000000000000000000000000000000000000000000000000000"),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{0}, 32)),
			},
		},
		{
			fmt.Errorf("ToL1Address(%s) is invalid", "01010101010101010101010101010101010101010101010101010101010101"),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 31)),
			},
		},
		// NftIndex
		{
			fmt.Errorf("NftIndex should not be less than %d", minNftIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         minNftIndex - 1,
			},
		},
		{
			fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         maxNftIndex + 1,
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         3,
				GasAccountIndex:  -1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         3,
				GasAccountIndex:  maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         3,
				GasAccountIndex:  0,
				GasFeeAssetId:    -1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   2,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         3,
				GasAccountIndex:  0,
				GasFeeAssetId:    maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&TransferNftTxInfo{
				FromAccountIndex: 1,
				ToL1Address:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:         3,
				GasAccountIndex:  0,
				GasFeeAssetId:    3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&TransferNftTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    2,
				ToL1Address:       hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:          3,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&TransferNftTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    2,
				ToL1Address:       hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:          3,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// CallDataHash
		{
			fmt.Errorf("CallDataHash(0000000000000000000000000000000000000000000000000000000000000000) is invalid"),
			&TransferNftTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    2,
				ToL1Address:       hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:          3,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				CallDataHash:      bytes.Repeat([]byte{0}, 32),
			},
		},
		{
			fmt.Errorf("CallDataHash(01010101010101010101010101010101010101010101010101010101010101) is invalid"),
			&TransferNftTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    2,
				ToL1Address:       hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:          3,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				CallDataHash:      bytes.Repeat([]byte{1}, 31),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&TransferNftTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    2,
				ToL1Address:       hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftIndex:          3,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				CallDataHash:      bytes.Repeat([]byte{1}, 32),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             -1,
			},
		},
	}

	for _, testCase := range testCases {
		err := testCase.testCase.Validate()
		require.Equalf(t, err, testCase.err, "err should be the same")
	}
}
