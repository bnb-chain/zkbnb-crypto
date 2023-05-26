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

package types

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

func CollectPubDataFromExit(api types.API, txInfo ExitTxConstraints) (pubData [types.PubDataBitsSizePerTx]types.Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeExit, types.TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, types.AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetId, types.AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetAmount, types.StateAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.L1Address, types.AddressBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < types.PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromExitNft(api types.API, txInfo ExitNftTxConstraints) (pubData [types.PubDataBitsSizePerTx]types.Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeExitNft, types.TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, types.AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountIndex, types.AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.RoyaltyRate, types.FeeRateBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, types.NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, types.CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.L1Address, types.AddressBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorL1Address, types.AddressBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash[0], types.HashBitsSize/2, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash[1], types.HashBitsSize/2, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentType, types.TxTypeBitsSize, &currentOffset, pubData[:])
	for i := currentOffset; i < types.PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func copyLittleEndianSliceAndShiftOffset(api types.API, txField types.Variable, txFiledBitsSize int, currentOffset *int, pubData []types.Variable) {
	txFiledBits := api.ToBinary(txField, txFiledBitsSize)
	types.CopyLittleEndianSlice(pubData[*currentOffset:*currentOffset+txFiledBitsSize], txFiledBits)
	*currentOffset += txFiledBitsSize
}
