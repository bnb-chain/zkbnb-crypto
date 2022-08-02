package legendTxTypes

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
		// CreatorAccountIndex
		{
			fmt.Errorf("CreatorAccountIndex should not be less than %d", minAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("CreatorAccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:        1,
				CreatorAccountIndex: maxAccountIndex + 1,
			},
		},
		// CreatorAccountNameHash
		{
			fmt.Errorf("CreatorAccountNameHash(0000000000000000000000000000000000000000000000000000000000000000) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{0}, 32),
			},
		},
		{
			fmt.Errorf("CreatorAccountNameHash(01010101010101010101010101010101010101010101010101010101010101) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 31),
			},
		},
		// CreatorTreasuryRate
		{
			fmt.Errorf("NftIndex should not be less than %d", minNftIndex),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               minNftIndex - 1,
			},
		},
		{
			fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               maxNftIndex + 1,
			},
		},
		// NftContentHash
		{
			fmt.Errorf("NftContentHash(0000000000000000000000000000000000000000000000000000000000000000) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{0}, 32),
			},
		},
		{
			fmt.Errorf("NftContentHash(01010101010101010101010101010101010101010101010101010101010101) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 31),
			},
		},
		// NftL1Address
		{
			fmt.Errorf("NftL1Address(0x11) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x11",
			},
		},
		// NftL1TokenId
		{
			fmt.Errorf("NftL1TokenId should not be less than 0"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(-1),
			},
		},
		// CollectionId
		{
			fmt.Errorf("CollectionId should not be less than %d", minCollectionId),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           minCollectionId - 1,
			},
		},
		{
			fmt.Errorf("CollectionId should not be larger than %d", maxCollectionId),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           maxCollectionId + 1,
			},
		},
		// ToAddress
		{
			fmt.Errorf("ToAddress(0x11) is invalid"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x11",
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
				GasFeeAssetAmount:      big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
				GasFeeAssetAmount:      big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// ExpiredAt
		{
			fmt.Errorf("ExpiredAt should be larger than 0"),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
				GasFeeAssetAmount:      big.NewInt(100),
				ExpiredAt:              0,
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
				GasFeeAssetAmount:      big.NewInt(100),
				ExpiredAt:              time.Now().Unix(),
				Nonce:                  0,
			},
		},
		// true
		{
			nil,
			&WithdrawNftTxInfo{
				AccountIndex:           1,
				CreatorAccountIndex:    1,
				CreatorAccountNameHash: bytes.Repeat([]byte{1}, 32),
				NftIndex:               5,
				NftContentHash:         bytes.Repeat([]byte{1}, 32),
				NftL1Address:           "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd9",
				NftL1TokenId:           big.NewInt(11),
				CollectionId:           11,
				ToAddress:              "0x299d17c8b4e9967385dc9a3bb78f2a43f5a13bd0",
				GasAccountIndex:        0,
				GasFeeAssetId:          3,
				GasFeeAssetAmount:      big.NewInt(100),
				ExpiredAt:              time.Now().Unix(),
				Nonce:                  1,
			},
		},
	}

	for _, testCase := range testCases {
		err := ValidateWithdrawNftTxInfo(testCase.testCase)
		require.Equalf(t, testCase.err, err, "err should be the same")
	}
}
