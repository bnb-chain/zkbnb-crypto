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

func TestValidateWithdrawTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *WithdrawTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&WithdrawTxInfo{
				FromAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// AssetId
		{
			fmt.Errorf("AssetId should not be less than %d", minAssetId),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetId should not be larger than %d", maxAssetId),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          maxAssetId + 1,
			},
		},
		// AssetAmount
		{
			fmt.Errorf("AssetAmount should not be nil"),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
			},
		},
		{
			fmt.Errorf("AssetAmount should not be less than %s", minAssetAmount.String()),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAmount should not be larger than %s", maxAssetAmount.String()),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&WithdrawTxInfo{
				FromAccountIndex: 1,
				AssetId:          1,
				AssetAmount:      big.NewInt(1),
				GasAccountIndex:  0,
				GasFeeAssetId:    3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&WithdrawTxInfo{
				FromAccountIndex:  1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&WithdrawTxInfo{
				FromAccountIndex:  1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&WithdrawTxInfo{
				FromAccountIndex:  1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				ToAddress:         "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             0,
			},
		},
		//  ToAddress
		{
			fmt.Errorf("ToAddress(0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd) is invalid"),
			&WithdrawTxInfo{
				FromAccountIndex:  1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				ToAddress:         "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd",
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
		// true
		{
			nil,
			&WithdrawTxInfo{
				FromAccountIndex:  1,
				AssetId:           1,
				AssetAmount:       big.NewInt(1),
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				ToAddress:         "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
	}
	for _, testCase := range testCases {
		err := testCase.testCase.Validate()
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
