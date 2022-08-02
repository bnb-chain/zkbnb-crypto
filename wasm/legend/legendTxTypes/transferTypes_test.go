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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateTransferTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *TransferTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// ToAccountIndex
		{
			fmt.Errorf("ToAccountIndex should not be less than %d", minAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("ToAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   maxAccountIndex + 1,
			},
		},
		// AssetId
		{
			fmt.Errorf("AssetId should not be less than %d", minAssetId),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetId should not be larger than %d", maxAssetId),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          maxAssetId + 1,
			},
		},
		// AssetAmount
		{
			fmt.Errorf("AssetAmount should not be nil"),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1, AssetId: 1,
			},
		},
		{
			fmt.Errorf("AssetAmount should not be less than %s", minAssetAmount.String()),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAmount should not be larger than %s", maxAssetAmount.String()),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&TransferTxInfo{
				FromAccountIndex: 1,
				ToAccountIndex:   1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&TransferTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&TransferTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt should be larger than 0"),
			&TransferTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         0,
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&TransferTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Unix(),
				Nonce:             0,
			},
		},
		// true
		{
			nil,
			&TransferTxInfo{
				FromAccountIndex:  1,
				ToAccountIndex:    1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Unix(),
				Nonce:             1,
			},
		},
	}
	for _, testCase := range testCases {
		err := ValidateTransferTxInfo(testCase.testCase)
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
