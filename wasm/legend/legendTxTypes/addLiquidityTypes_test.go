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

func TestValidateAddLiquidityTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *AddLiquidityTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// PairIndex
		{
			fmt.Errorf("PairIndex should not be less than %d", minPairIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("PairIndex should not be larger than %d", maxPairIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        maxAccountIndex + 1,
			},
		},
		// AssetAAmount
		{
			fmt.Errorf("AssetAAmount should not be nil"),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
			},
		},
		{
			fmt.Errorf("AssetAAmount should not be less than %s", minAssetAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAAmount should not be larger than %s", maxAssetAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// AssetBAmount
		{
			fmt.Errorf("AssetBAmount should not be nil"),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
			},
		},
		{
			fmt.Errorf("AssetBAmount should not be less than %s", minAssetAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetBAmount should not be larger than %s", maxAssetAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(1),
				LpAmount:         big.NewInt(1),
				GasAccountIndex:  minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(1),
				LpAmount:         big.NewInt(1),
				GasAccountIndex:  maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(1),
				LpAmount:         big.NewInt(1),
				GasAccountIndex:  1,
				GasFeeAssetId:    minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(1),
				LpAmount:         big.NewInt(1),
				GasAccountIndex:  1,
				GasFeeAssetId:    maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&AddLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBAmount:     big.NewInt(1),
				LpAmount:         big.NewInt(1),
				GasAccountIndex:  1,
				GasFeeAssetId:    3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBAmount:      big.NewInt(1),
				LpAmount:          big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&AddLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBAmount:      big.NewInt(1),
				LpAmount:          big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&AddLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBAmount:      big.NewInt(1),
				LpAmount:          big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(1),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
			},
		},
		// true
		{
			nil,
			&AddLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBAmount:      big.NewInt(1),
				LpAmount:          big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(1),
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
