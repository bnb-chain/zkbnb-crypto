package txtypes

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateCreateCollectionTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *CreateCollectionTxInfo
	}{
		// AccountIndex
		{
			fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex),
			&CreateCollectionTxInfo{
				AccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex),
			&CreateCollectionTxInfo{
				AccountIndex: maxAccountIndex + 1,
			},
		},
		// Name
		{
			fmt.Errorf("length of Name should not be less than %d", minCollectionNameLength),
			&CreateCollectionTxInfo{
				AccountIndex: 1,
				CollectionId: 5,
				Name:         "",
			},
		},
		{
			fmt.Errorf("length of Name should not be larger than %d", maxCollectionNameLength),
			&CreateCollectionTxInfo{
				AccountIndex: 1,
				CollectionId: 5,
				Name:         strings.Repeat("t", maxCollectionNameLength+1),
			},
		},
		// Introduction
		{
			fmt.Errorf("length of Introduction should not be larger than %d", maxCollectionIntroductionLength),
			&CreateCollectionTxInfo{
				AccountIndex: 1,
				CollectionId: 5,
				Name:         "test name",
				Introduction: strings.Repeat("s", maxCollectionIntroductionLength+1),
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&CreateCollectionTxInfo{
				AccountIndex:    1,
				CollectionId:    5,
				Name:            "test name",
				Introduction:    "test introduction",
				GasAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&CreateCollectionTxInfo{
				AccountIndex:    1,
				CollectionId:    5,
				Name:            "test name",
				Introduction:    "test introduction",
				GasAccountIndex: maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&CreateCollectionTxInfo{
				AccountIndex:    1,
				CollectionId:    5,
				Name:            "test name",
				Introduction:    "test introduction",
				GasAccountIndex: 0,
				GasFeeAssetId:   minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&CreateCollectionTxInfo{
				AccountIndex:    1,
				CollectionId:    5,
				Name:            "test name",
				Introduction:    "test introduction",
				GasAccountIndex: 0,
				GasFeeAssetId:   maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&CreateCollectionTxInfo{
				AccountIndex:    1,
				CollectionId:    5,
				Name:            "test name",
				Introduction:    "test introduction",
				GasAccountIndex: 0,
				GasFeeAssetId:   3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&CreateCollectionTxInfo{
				AccountIndex:      1,
				CollectionId:      5,
				Name:              "test name",
				Introduction:      "test introduction",
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&CreateCollectionTxInfo{
				AccountIndex:      1,
				CollectionId:      5,
				Name:              "test name",
				Introduction:      "test introduction",
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&CreateCollectionTxInfo{
				AccountIndex:      1,
				CollectionId:      5,
				Name:              "test name",
				Introduction:      "test introduction",
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             -1,
			},
		},
		// true
		{
			nil,
			&CreateCollectionTxInfo{
				AccountIndex:      1,
				CollectionId:      5,
				Name:              "test name",
				Introduction:      "test introduction",
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
	}

	for _, testCase := range testCases {
		err := testCase.testCase.Validate()
		require.Equalf(t, err, testCase.err, "err should be the same")
	}
}
