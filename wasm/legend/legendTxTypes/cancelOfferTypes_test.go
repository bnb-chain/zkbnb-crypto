package legendTxTypes

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateCancelOfferTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *CancelOfferTxInfo
	}{
		// AccountIndex
		{
			fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex),
			&CancelOfferTxInfo{
				AccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex),
			&CancelOfferTxInfo{
				AccountIndex: maxAccountIndex + 1,
			},
		},
		// OfferId
		{
			fmt.Errorf("OfferId should not be less than 0"),
			&CancelOfferTxInfo{
				AccountIndex: 1,
				OfferId:      -1,
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&CancelOfferTxInfo{
				AccountIndex:    1,
				OfferId:         1,
				GasAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&CancelOfferTxInfo{
				AccountIndex:    1,
				OfferId:         1,
				GasAccountIndex: maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&CancelOfferTxInfo{
				AccountIndex:    1,
				OfferId:         1,
				GasAccountIndex: 0,
				GasFeeAssetId:   minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&CancelOfferTxInfo{
				AccountIndex:    1,
				OfferId:         1,
				GasAccountIndex: 0,
				GasFeeAssetId:   maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&CancelOfferTxInfo{
				AccountIndex:    1,
				OfferId:         1,
				GasAccountIndex: 0,
				GasFeeAssetId:   3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&CancelOfferTxInfo{
				AccountIndex:      1,
				OfferId:           1,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&CancelOfferTxInfo{
				AccountIndex:      1,
				OfferId:           1,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt(ms) should be after now"),
			&CancelOfferTxInfo{
				AccountIndex:      1,
				OfferId:           1,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         0,
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&CancelOfferTxInfo{
				AccountIndex:      1,
				OfferId:           1,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             0,
			},
		},
		// true
		{
			nil,
			&CancelOfferTxInfo{
				AccountIndex:      1,
				OfferId:           1,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
	}

	for _, testCase := range testCases {
		err := ValidateCancelOfferTxInfo(testCase.testCase)
		require.Equalf(t, err, testCase.err, "err should be the same")
	}
}
