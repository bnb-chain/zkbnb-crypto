package legendTxTypes

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateAtomicMatchTxInfo(t *testing.T) {
	validOffer := &OfferTxInfo{
		Type:         1,
		OfferId:      1,
		AccountIndex: 3,
		NftIndex:     4,
		AssetId:      10,
		AssetAmount:  big.NewInt(20),
		ListedAt:     time.Now().Add(time.Hour).UnixMilli(),
		ExpiredAt:    time.Now().Add(time.Hour).UnixMilli(),
		TreasuryRate: 10,
	}

	testCases := []struct {
		err      error
		testCase *AtomicMatchTxInfo
	}{
		// AccountIndex
		{
			fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex),
			&AtomicMatchTxInfo{
				AccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex),
			&AtomicMatchTxInfo{
				AccountIndex: maxAccountIndex + 1,
			},
		},
		// BuyOffer
		{
			fmt.Errorf("BuyOffer should not be nil"),
			&AtomicMatchTxInfo{
				AccountIndex: 1,
			},
		},
		{
			fmt.Errorf("SellOffer should not be nil"),
			&AtomicMatchTxInfo{
				AccountIndex: 1,
				BuyOffer:     validOffer,
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&AtomicMatchTxInfo{
				AccountIndex:    1,
				BuyOffer:        validOffer,
				SellOffer:       validOffer,
				GasAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&AtomicMatchTxInfo{
				AccountIndex:    1,
				BuyOffer:        validOffer,
				SellOffer:       validOffer,
				GasAccountIndex: maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&AtomicMatchTxInfo{
				AccountIndex:    1,
				BuyOffer:        validOffer,
				SellOffer:       validOffer,
				GasAccountIndex: 0,
				GasFeeAssetId:   minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&AtomicMatchTxInfo{
				AccountIndex:    1,
				BuyOffer:        validOffer,
				SellOffer:       validOffer,
				GasAccountIndex: 0,
				GasFeeAssetId:   maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&AtomicMatchTxInfo{
				AccountIndex:    1,
				BuyOffer:        validOffer,
				SellOffer:       validOffer,
				GasAccountIndex: 0,
				GasFeeAssetId:   3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt(ms) should be after now"),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         0,
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             0,
			},
		},
		// CreatorAmount
		{
			fmt.Errorf("CreatorAmount should not be nil"),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
			},
		},
		{
			fmt.Errorf("CreatorAmount should not be less than %s", minAssetAmount.String()),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
				CreatorAmount:     big.NewInt(0).Sub(minAssetAmount, big.NewInt(1)),
			},
		},
		{
			fmt.Errorf("CreatorAmount should not be larger than %s", maxAssetAmount.String()),
			&AtomicMatchTxInfo{
				AccountIndex:      1,
				BuyOffer:          validOffer,
				SellOffer:         validOffer,
				GasAccountIndex:   0,
				GasFeeAssetId:     3,
				GasFeeAssetAmount: big.NewInt(100),
				ExpiredAt:         time.Now().Add(time.Hour).UnixMilli(),
				Nonce:             1,
				CreatorAmount:     big.NewInt(0).Add(maxAssetAmount, big.NewInt(1)),
			},
		},
	}

	for _, testCase := range testCases {
		err := ValidateAtomicMatchTxInfo(testCase.testCase)
		require.Equalf(t, err, testCase.err, "err should be the same")
	}
}
