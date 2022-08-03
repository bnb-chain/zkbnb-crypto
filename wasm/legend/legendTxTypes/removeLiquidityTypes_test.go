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

func TestValidateRemoveLiquidityTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *RemoveLiquidityTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// PairIndex
		{
			fmt.Errorf("PairIndex should not be less than %d", minPairIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("PairIndex should not be larger than %d", maxPairIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        maxAccountIndex + 1,
			},
		},
		// AssetAId
		{
			fmt.Errorf("AssetAId should not be less than %d", minAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetAId should not be larger than %d", maxAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         maxAssetId + 1,
			},
		},
		// AssetAMinAmount
		{
			fmt.Errorf("AssetAMinAmount should not be nil"),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
			},
		},
		{
			fmt.Errorf("AssetAMinAmount should not be less than %s", minAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAMinAmount should not be larger than %s", maxAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// AssetBId
		{
			fmt.Errorf("AssetBId should not be less than %d", minAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetBId should not be larger than %d", maxAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         maxAssetId + 1,
			},
		},
		// AssetBMinAmount
		{
			fmt.Errorf("AssetBMinAmount should not be nil"),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
			},
		},
		{
			fmt.Errorf("AssetBMinAmount should not be less than %s", minAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetBMinAmount should not be larger than %s", maxAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// LpAmount
		{
			fmt.Errorf("LpAmount should not be nil"),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(1),
			},
		},
		{
			fmt.Errorf("LpAmount should not be less than %s", minAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(1),
				LpAmount:         big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("LpAmount should not be larger than %s", maxAssetAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAMinAmount:  big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(1),
				LpAmount:         big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt(ms) should be after now"),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(1),
				ExpiredAt:         0,
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(1),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
			},
		},
		// true
		{
			nil,
			&RemoveLiquidityTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAMinAmount:   big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				LpAmount:          big.NewInt(1),
				AssetAAmountDelta: big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(1),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
	}
	for _, testCase := range testCases {
		err := ValidateRemoveLiquidityTxInfo(testCase.testCase)
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
