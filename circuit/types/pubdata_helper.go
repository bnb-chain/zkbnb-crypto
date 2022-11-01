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

func CollectPubDataFromRegisterZNS(api API, txInfo RegisterZnsTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeRegisterZns, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountName, AccountNameBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountNameHash, HashBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.PubKey.A.X, PubkeyBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.PubKey.A.Y, PubkeyBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDeposit(api API, txInfo DepositTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeDeposit, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetAmount, StateAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountNameHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDepositNft(api API, txInfo DepositNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeDepositNft, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash, HashBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountNameHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransfer(api API, txInfo TransferTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeTransfer, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.FromAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.ToAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetAmount, PackedAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CallDataHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdraw(api API, txInfo WithdrawTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeWithdraw, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.FromAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.ToAddress, AddressBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetAmount, StateAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCreateCollection(api API, txInfo CreateCollectionTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeCreateCollection, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromMintNft(api API, txInfo MintNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeMintNft, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.ToAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransferNft(api API, txInfo TransferNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeTransferNft, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.FromAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.ToAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CallDataHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromAtomicMatch(api API, txInfo AtomicMatchTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeAtomicMatch, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.BuyOffer.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.BuyOffer.OfferId, OfferIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.SellOffer.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.SellOffer.OfferId, OfferIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.BuyOffer.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.SellOffer.AssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.SellOffer.AssetAmount, PackedAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAmount, PackedAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.TreasuryAmount, PackedAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCancelOffer(api API, txInfo CancelOfferTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeCancelOffer, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.OfferId, OfferIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdrawNft(api API, txInfo WithdrawNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeWithdrawNft, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorTreasuryRate, FeeRateBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.ToAddress, AddressBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.GasFeeAssetAmount, PackedFeeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash, HashBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountNameHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromFullExit(api API, txInfo FullExitTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeFullExit, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetId, AssetIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AssetAmount, StateAmountBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountNameHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromFullExitNft(api API, txInfo FullExitNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	copyLittleEndianSliceAndShiftOffset(api, TxTypeFullExitNft, TxTypeBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountIndex, AccountIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorTreasuryRate, FeeRateBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftIndex, NftIndexBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CollectionId, CollectionIdBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.AccountNameHash, HashBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.CreatorAccountNameHash, HashBitsSize, &currentOffset, pubData[:])
	copyLittleEndianSliceAndShiftOffset(api, txInfo.NftContentHash, HashBitsSize, &currentOffset, pubData[:])

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}
