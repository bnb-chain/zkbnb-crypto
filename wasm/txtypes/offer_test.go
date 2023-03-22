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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateOfferTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *OfferTxInfo
	}{
		// Type
		{
			fmt.Errorf("Type should only be buy(%d) and sell(%d)", BuyOfferType, SellOfferType),
			&OfferTxInfo{
				Type: 3,
			},
		},
		// OfferId
		{
			fmt.Errorf("OfferId should not be less than 0"),
			&OfferTxInfo{
				Type:    1,
				OfferId: -1,
			},
		},
		// AccountIndex
		{
			fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: -1,
			},
		},
		{
			fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: maxAccountIndex + 1,
			},
		},
		// NftIndex
		{
			fmt.Errorf("NftIndex should not be less than %d", minNftIndex),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     minNftIndex - 1,
			},
		},
		{
			fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     maxNftIndex + 1,
			},
		},
		// AssetId
		{
			fmt.Errorf("AssetId should not be less than %d", minAssetId),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      -1,
			},
		},
		{
			fmt.Errorf("AssetId should not be larger than %d", maxAssetId),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      maxAssetId + 1,
			},
		},
		// AssetAmount
		{
			fmt.Errorf("AssetAmount should not be nil"),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
			},
		},
		{
			fmt.Errorf("AssetAmount should be larger than %s", minAssetAmount.String()),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
				AssetAmount:  big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("AssetAmount should not be larger than %s", maxAssetAmount.String()),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
				AssetAmount:  big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
		// ListedAt
		{
			fmt.Errorf("ListedAt should be larger than 0"),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
				AssetAmount:  big.NewInt(20),
				ListedAt:     0,
			},
		},
		// TreasuryRate
		{
			fmt.Errorf("TreasuryRate should  not be less than %d", minRate),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
				AssetAmount:  big.NewInt(20),
				ListedAt:     time.Now().Unix(),
				ExpiredAt:    time.Now().Add(time.Hour).UnixMilli(),
				TreasuryRate: minRate - 1,
			},
		},
		{
			fmt.Errorf("TreasuryRate should not be larger than %d", maxRate),
			&OfferTxInfo{
				Type:         1,
				OfferId:      1,
				AccountIndex: 3,
				NftIndex:     4,
				AssetId:      10,
				AssetAmount:  big.NewInt(20),
				ListedAt:     time.Now().Unix(),
				ExpiredAt:    time.Now().Add(time.Hour).UnixMilli(),
				TreasuryRate: maxRate + 1,
			},
		},
	}

	for index, testCase := range testCases {
		err := testCase.testCase.Validate()
		require.Equalf(t, err, testCase.err, fmt.Sprintf("case %d: err should be the same", index))
	}
}
