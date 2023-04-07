package txtypes

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateWithdrawNftTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *WithdrawNftTxInfo
	}{
		// AccountIndex
		{
			fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex: maxAccountIndex + 1,
			},
		},
		// NftIndex
		{
			fmt.Errorf("NftIndex should not be less than %d", minNftIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            minNftIndex - 1,
			},
		},
		{
			fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            maxNftIndex + 1,
			},
		},
		// ToAddress
		{
			fmt.Errorf("ToAddress(0x11) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x11",
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(100),
				ExpiredAt:           time.Now().Add(time.Hour).UnixMilli(),
				Nonce:               -1,
			},
		},
		// true
		{
			nil,
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: 1,
				CreatorL1Address:    "",
				NftIndex:            5,
				NftContentHash:      bytes.Repeat([]byte{1}, 32),
				CollectionId:        11,
				ToAddress:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(100),
				ExpiredAt:           time.Now().Add(time.Hour).UnixMilli(),
				Nonce:               1,
			},
		},
	}

	for _, testCase := range testCases {
		err := testCase.testCase.Validate()
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
