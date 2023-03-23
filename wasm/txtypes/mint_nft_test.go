package txtypes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateMintNftTxInfo(t *testing.T) {
	testCases := []struct {
		err      error
		testCase *MintNftTxInfo
	}{
		// CreatorAccountIndex
		{
			fmt.Errorf("CreatorAccountIndex should not be less than %d", minAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("CreatorAccountIndex should not be larger than %d", maxAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: maxAccountIndex + 1,
			},
		},
		// ToAccountIndex
		{
			fmt.Errorf("ToAccountIndex should not be less than %d", minAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("ToAccountIndex should not be larger than %d", maxAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      maxAccountIndex + 1,
			},
		},
		// ToL1Address
		{
			fmt.Errorf("ToL1Address(0000000000000000000000000000000000000000000000000000000000000000) is invalid"),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{0}, 32)),
			},
		},
		{
			fmt.Errorf("ToL1Address(01010101010101010101010101010101010101010101010101010101010101) is invalid"),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 31)),
			},
		},
		// NftContentHash
		{
			fmt.Errorf("NftContentHash(0000000000000000000000000000000000000000000000000000000000000000) is invalid"),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{0}, 32)),
			},
		},
		{
			fmt.Errorf("NftContentHash(01010101010101010101010101010101010101010101010101010101010101) is invalid"),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 31)),
			},
		},
		// NftCollectionId
		{
			fmt.Errorf("NftCollectionId should not be less than %d", minCollectionId),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     minCollectionId - 1,
			},
		},
		{
			fmt.Errorf("NftCollectionId should not be larger than %d", maxCollectionId),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     maxCollectionId + 1,
			},
		},
		// RoyaltyRate
		{
			fmt.Errorf("RoyaltyRate should  not be less than %d", minRate),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         minRate - 1,
			},
		},
		{
			fmt.Errorf("RoyaltyRate should not be larger than %d", maxRate),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         maxRate + 1,
			},
		},
		// GasAccountIndex
		{
			fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     minAccountIndex - 1,
			},
		},
		{
			fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     maxAccountIndex + 1,
			},
		},
		// GasFeeAssetId
		{
			fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     0,
				GasFeeAssetId:       minAssetId - 1,
			},
		},
		{
			fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     0,
				GasFeeAssetId:       maxAssetId + 1,
			},
		},
		// GasFeeAssetAmount
		{
			fmt.Errorf("GasFeeAssetAmount should not be nil"),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String()),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(-1),
			},
		},
		{
			fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String()),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
				GasAccountIndex:     0,
				GasFeeAssetId:       3,
				GasFeeAssetAmount:   big.NewInt(0).Add(maxPackedFeeAmount, big.NewInt(1)),
			},
		},
		// Nonce
		{
			fmt.Errorf("Nonce should not be less than %d", minNonce),
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
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
			&MintNftTxInfo{
				CreatorAccountIndex: 1,
				ToAccountIndex:      2,
				ToL1Address:         hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftContentHash:      hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				NftCollectionId:     4,
				RoyaltyRate:         10,
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
		require.Equalf(t, err, testCase.err, "err should be the same")
	}
}
