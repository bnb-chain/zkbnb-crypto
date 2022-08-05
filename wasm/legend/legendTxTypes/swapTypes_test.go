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

func TestValidateSwapTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *SwapTxInfo
	}{
		// FromAccountIndex
		{
			fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex),
			&SwapTxInfo{
				FromAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex),
			&SwapTxInfo{
				FromAccountIndex: maxAccountIndex + 1,
			},
		},
		// PairIndex
		{
			fmt.Errorf("PairIndex should not be less than %d", minPairIndex),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("PairIndex should not be larger than %d", maxPairIndex),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        maxAccountIndex + 1,
			},
		},
		// AssetAId
		{
			fmt.Errorf("AssetAId should not be less than %d", minAssetId),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetAId should not be larger than %d", maxAssetId),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         maxAssetId + 1,
			},
		},
		// AssetAAmount
		{
			fmt.Errorf("AssetAAmount should not be nil"),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
			},
		},
		{
			fmt.Errorf("AssetAAmount should not be less than %s", minAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAAmount should not be larger than %s", maxAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// AssetBId
		{
			fmt.Errorf("AssetBId should not be less than %d", minAssetId),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         minAssetId - 1,
			},
		},
		{
			fmt.Errorf("AssetBId should not be larger than %d", maxAssetId),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         maxAssetId + 1,
			},
		},
		// AssetBMinAmount
		{
			fmt.Errorf("AssetBMinAmount should not be nil"),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
			},
		},
		{
			fmt.Errorf("AssetBMinAmount should not be less than %s", minAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetBMinAmount should not be larger than %s", maxAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// AssetBAmountDelta
		{
			fmt.Errorf("AssetBAmountDelta should not be nil"),
			&SwapTxInfo{
				FromAccountIndex: 1,
				PairIndex:        1,
				AssetAId:         1,
				AssetAAmount:     big.NewInt(1),
				AssetBId:         1,
				AssetBMinAmount:  big.NewInt(1),
			},
		},
		{
			fmt.Errorf("AssetBAmountDelta should not be less than %s", minAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetBAmountDelta should not be larger than %s", maxAssetAmount.String()),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
				AssetBAmountDelta: big.NewInt(1),
				GasAccountIndex:   1,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt(ms) should be after now"),
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
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
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
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
			&SwapTxInfo{
				FromAccountIndex:  1,
				PairIndex:         1,
				AssetAId:          1,
				AssetAAmount:      big.NewInt(1),
				AssetBId:          1,
				AssetBMinAmount:   big.NewInt(1),
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
		err := ValidateSwapTxInfo(testCase.testCase)
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
