package circuit

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type GasAssetConstraints struct {
	AssetId Variable
	Balance Variable
}

type GasAccountConstraints struct {
	AccountIndex    Variable
	AccountNameHash Variable
	AccountPk       eddsa.PublicKey
	Nonce           Variable
	CollectionNonce Variable
	AssetRoot       Variable
	AssetsInfo      []GasAssetConstraints
	GasAssetCount   int
}

type GasConstraints struct {
	GasAssetCount                   int
	AccountInfoBefore               GasAccountConstraints
	MerkleProofsAccountBefore       [AccountMerkleLevels]Variable
	MerkleProofsAccountAssetsBefore [][AssetMerkleLevels]Variable
}

func VerifyGas(
	api API,
	gas GasConstraints,
	gasAssetDeltas []Variable,
	hFunc MiMC,
	lastRoots [types.NbRoots]Variable) (newStateRoot Variable, err error) {
	notEmptyTx := 1
	NewAccountRoot := lastRoots[0]
	var (
		NewAccountAssetsRoot = gas.AccountInfoBefore.AssetRoot
	)

	gasAssetCount := len(gasAssetDeltas)
	deltas := make([]AccountAssetDeltaConstraints, gasAssetCount)

	for i := 0; i < gasAssetCount; i++ {
		deltas[i] = AccountAssetDeltaConstraints{
			BalanceDelta:             gasAssetDeltas[i],
			LpDelta:                  types.ZeroInt,
			OfferCanceledOrFinalized: types.ZeroInt,
		}
	}
	AccountsInfoAfter := UpdateGasAccount(api, gas.AccountInfoBefore, gasAssetCount, deltas)

	// verify account asset node hash
	for i := 0; i < gasAssetCount; i++ {
		assetMerkleHelper := AssetIdToMerkleHelper(api, gas.AccountInfoBefore.AssetsInfo[i].AssetId)
		hFunc.Reset()
		hFunc.Write(
			gas.AccountInfoBefore.AssetsInfo[i].Balance,
			types.ZeroInt,
			types.ZeroInt,
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
			types.ZeroInt,
			types.ZeroInt,
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
		lastRoots[1],
		lastRoots[2],
	)
	newStateRoot = hFunc.Sum()
	return newStateRoot, err
}

func UpdateGasAccount(
	api API,
	accountInfo GasAccountConstraints,
	gasAssetCount int,
	gasAssetsDeltas []AccountAssetDeltaConstraints,
) (accountInfoAfter GasAccountConstraints) {
	accountInfoAfter = accountInfo
	for i := 0; i < gasAssetCount; i++ {
		accountInfoAfter.AssetsInfo[i].Balance = api.Add(
			accountInfo.AssetsInfo[i].Balance,
			gasAssetsDeltas[i].BalanceDelta)
	}
	return accountInfoAfter
}

func GetZeroGasConstraints(gasAssetCount int) GasConstraints {
	var zeroGasConstraint GasConstraints
	zeroGasConstraint.GasAssetCount = gasAssetCount

	// set witness
	zeroAccountConstraint := GasAccountConstraints{
		AccountIndex:    0,
		AccountNameHash: 0,
		AccountPk:       types.EmptyPublicKeyWitness(),
		Nonce:           0,
		CollectionNonce: 0,
		AssetRoot:       0,
		GasAssetCount:   gasAssetCount,
	}
	zeroAccountConstraint.AssetsInfo = make([]GasAssetConstraints, gasAssetCount)
	// set assets witness
	for i := 0; i < gasAssetCount; i++ {
		zeroAccountConstraint.AssetsInfo[i] = GasAssetConstraints{
			AssetId: 0,
			Balance: 0,
		}
	}
	// accounts info before
	zeroGasConstraint.AccountInfoBefore = zeroAccountConstraint
	zeroGasConstraint.MerkleProofsAccountAssetsBefore = make([][AssetMerkleLevels]Variable, gasAssetCount)
	for j := 0; j < gasAssetCount; j++ {
		for k := 0; k < AssetMerkleLevels; k++ {
			// account assets before
			zeroGasConstraint.MerkleProofsAccountAssetsBefore[j][k] = 0
		}
	}
	for j := 0; j < AccountMerkleLevels; j++ {
		// account before
		zeroGasConstraint.MerkleProofsAccountBefore[j] = 0
	}

	return zeroGasConstraint
}
