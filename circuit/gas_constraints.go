package circuit

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

type GasAccountConstraints struct {
	AccountIndex    Variable
	AccountNameHash Variable
	AccountPk       eddsa.PublicKey
	Nonce           Variable
	CollectionNonce Variable
	AssetRoot       Variable
	AssetsInfo      [types.NbGasAssets]types.AccountAssetConstraints
}

type GasConstraints struct {
	AccountInfoBefore               GasAccountConstraints
	MerkleProofsAccountBefore       [AccountMerkleLevels]Variable
	MerkleProofsAccountAssetsBefore [types.NbGasAssets][AssetMerkleLevels]Variable
	AssetIds                        [types.NbGasAssets][]Variable
	AssetAmounts                    [types.NbGasAssets][]Variable
}

func VerifyGas(
	api API,
	gas GasConstraints,
	hFunc MiMC,
	lastRoots [types.NbRoots]Variable) (newStateRoot Variable, err error) {
	notEmptyTx := 1
	NewAccountRoot := lastRoots[0]
	var (
		NewAccountAssetsRoot = gas.AccountInfoBefore.AssetRoot
		deltas               [types.NbGasAssets]AccountAssetDeltaConstraints
	)

	for i := 0; i < types.NbGasAssets; i++ {
		deltas[i] = AccountAssetDeltaConstraints{
			BalanceDelta:             gas.AssetAmounts[i],
			LpDelta:                  types.ZeroInt,
			OfferCanceledOrFinalized: types.ZeroInt,
		}
	}
	AccountsInfoAfter := UpdateGasAccount(api, gas.AccountInfoBefore, deltas)

	// verify account asset node hash
	for i := 0; i < types.NbGasAssets; i++ {
		api.AssertIsLessOrEqual(gas.AccountInfoBefore.AssetsInfo[i].AssetId, LastAccountAssetId)
		assetMerkleHelper := AssetIdToMerkleHelper(api, gas.AccountInfoBefore.AssetsInfo[i].AssetId)
		hFunc.Reset()
		hFunc.Write(
			gas.AccountInfoBefore.AssetsInfo[i].Balance,
			gas.AccountInfoBefore.AssetsInfo[i].LpAmount,
			gas.AccountInfoBefore.AssetsInfo[i].OfferCanceledOrFinalized,
		)
		assetNodeHash := hFunc.Sum()
		// verify account asset merkle proof
		hFunc.Reset()
		types.VerifyMerkleProof(
			api,
			notEmptyTx,
			hFunc,
			NewAccountAssetsRoot,
			assetNodeHash,
			gas.MerkleProofsAccountAssetsBefore[i][:],
			assetMerkleHelper,
		)
		hFunc.Reset()
		hFunc.Write(
			AccountsInfoAfter.AssetsInfo[i].Balance,
			AccountsInfoAfter.AssetsInfo[i].LpAmount,
			AccountsInfoAfter.AssetsInfo[i].OfferCanceledOrFinalized,
		)
		assetNodeHash = hFunc.Sum()
		hFunc.Reset()
		// update merkle proof
		NewAccountAssetsRoot = types.UpdateMerkleProof(
			api, hFunc, assetNodeHash, gas.MerkleProofsAccountAssetsBefore[i][:], assetMerkleHelper)
	}
	// verify account node hash
	api.AssertIsEqual(gas.AccountInfoBefore.AccountIndex, 1)
	accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, gas.AccountInfoBefore.AccountIndex)
	hFunc.Reset()
	hFunc.Write(
		gas.AccountInfoBefore.AccountNameHash,
		gas.AccountInfoBefore.AccountPk.A.X,
		gas.AccountInfoBefore.AccountPk.A.Y,
		gas.AccountInfoBefore.Nonce,
		gas.AccountInfoBefore.CollectionNonce,
		gas.AccountInfoBefore.AssetRoot,
	)
	accountNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	types.VerifyMerkleProof(
		api,
		notEmptyTx,
		hFunc,
		NewAccountRoot,
		accountNodeHash,
		gas.MerkleProofsAccountBefore[:],
		accountIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		AccountsInfoAfter.AccountNameHash,
		AccountsInfoAfter.AccountPk.A.X,
		AccountsInfoAfter.AccountPk.A.Y,
		AccountsInfoAfter.Nonce,
		AccountsInfoAfter.CollectionNonce,
		NewAccountAssetsRoot,
	)
	accountNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewAccountRoot = types.UpdateMerkleProof(api, hFunc, accountNodeHash, gas.MerkleProofsAccountBefore[:], accountIndexMerkleHelper)

	hFunc.Reset()
	hFunc.Write(
		NewAccountRoot,
		lastRoots[0],
		lastRoots[1],
	)
	newStateRoot = hFunc.Sum()
	return newStateRoot, err
}

func UpdateGasAccount(
	api API,
	accountInfo GasAccountConstraints,
	accountAssetsDeltas [types.NbGasAssets]AccountAssetDeltaConstraints,
) (accountInfoAfter GasAccountConstraints) {
	accountInfoAfter = accountInfo
	for i := 0; i < types.NbGasAssets; i++ {
		accountInfoAfter.AssetsInfo[i].Balance = api.Add(
			accountInfo.AssetsInfo[i].Balance,
			accountAssetsDeltas[i].BalanceDelta)
	}
	return accountInfoAfter
}
