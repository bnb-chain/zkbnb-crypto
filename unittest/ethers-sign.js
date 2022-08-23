const ethSignUtl = require('@metamask/eth-sig-util');

const main = async () => {
    const type = process.argv.slice(2)[0]
    // ethers (create random new account)
    let privateKey = Buffer.from(
        'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        'hex',
    );

    let version = ethSignUtl.SignTypedDataVersion.V4
    const types = {
        EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
            { name: 'salt', type: 'bytes32' },
        ],
        Transfer: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'ToAccountIndex', type: 'uint256' },
            { name: 'ToAccountNameHash', type: 'bytes32' },
            { name: 'AssetId', type: 'uint256' },
            { name: 'packedAmount', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'packedFee', type: 'uint256' },
            { name: 'CallDataHash', type: 'bytes32' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        Withdraw: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'AssetId', type: 'uint256' },
            { name: 'AssetAmount', type: 'bytes16' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ToAddress', type: 'bytes20' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        AddLiquidity: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'PairIndex', type: 'uint256' },
            { name: 'AssetAAmount', type: 'uint256' },
            { name: 'AssetBAmount', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        RemoveLiquidity: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'PairIndex', type: 'uint256' },
            { name: 'AssetAMinAmount', type: 'uint256' },
            { name: 'AssetBMinAmount', type: 'uint256' },
            { name: 'LpAmount', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        Swap: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'PairIndex', type: 'uint256' },
            { name: 'AssetAAmount', type: 'uint256' },
            { name: 'AssetBMinAmount', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        CreateCollection: [
            { name: 'AccountIndex', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        MintNft: [
            { name: 'CreatorAccountIndex', type: 'uint256' },
            { name: 'ToAccountIndex', type: 'uint256' },
            { name: 'ToAccountNameHash', type: 'bytes32' },
            { name: 'NftContentHash', type: 'bytes32' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'CreatorTreasuryRate', type: 'uint256' },
            { name: 'NftCollectionId', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        TransferNft: [
            { name: 'FromAccountIndex', type: 'uint256' },
            { name: 'ToAccountIndex', type: 'uint256' },
            { name: 'ToAccountNameHash', type: 'bytes32' },
            { name: 'NftIndex', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'CallDataHash', type: 'bytes32' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        WithdrawNft: [
            { name: 'AccountIndex', type: 'uint256' },
            { name: 'NftIndex', type: 'uint256' },
            { name: 'ToAddress', type: 'bytes20' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        CancelOffer: [
            { name: 'AccountIndex', type: 'uint256' },
            { name: 'OfferId', type: 'uint256' },
            { name: 'GasAccountIndex', type: 'uint256' },
            { name: 'GasFeeAssetId', type: 'uint256' },
            { name: 'GasFeeAssetAmount', type: 'uint256' },
            { name: 'ExpiredAt', type: 'uint256' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
        AtomicMatch: [
            { name: 'sellerAccountIndex', type: 'uint256' },
            { name: 'sellerNftIndex', type: 'uint256' },
            { name: 'sellerOfferId', type: 'uint256' },
            { name: 'sellerType', type: 'uint256' },
            { name: 'sellerAssetId', type: 'uint256' },
            { name: 'sellerAssetAmount', type: 'uint256' },
            { name: 'sellerListedAt', type: 'uint256' },
            { name: 'sellerExpiredAt', type: 'uint256' },
            { name: 'sellerTreasureRate', type: 'uint256' },
            { name: 'sellerSigR', type: 'bytes32' },
            { name: 'sellerSigS', type: 'bytes32' },
            { name: 'buyerAccountIndex', type: 'uint256' },
            { name: 'buyerNftIndex', type: 'uint256' },
            { name: 'buyerOfferId', type: 'uint256' },
            { name: 'buyerType', type: 'uint256' },
            { name: 'buyerAssetId', type: 'uint256' },
            { name: 'buyerAssetAmount', type: 'uint256' },
            { name: 'buyerListedAt', type: 'uint256' },
            { name: 'buyerExpiredAt', type: 'uint256' },
            { name: 'buyerTreasureRate', type: 'uint256' },
            { name: 'buyerSigR', type: 'bytes32' },
            { name: 'buyerSigS', type: 'bytes32' },
            { name: 'Nonce', type: 'uint256' },
            { name: 'ChainId', type: 'uint256' },
        ],
    };

    const primaryType = type;
    const hash16 = Buffer.from(
        '30000000000000000000000000000000',
        'hex',
    );
    const hash =
        '0x3000000000000000000000000000000000000000000000000000000000000000';
    const chash =
        '0x3000000000000000000000000000000000000000000000000000000000000000';
    const hash20 = '0x3000000000000000000000000000000000000000';
    const salt =
        '0xf2d857f4a3edcb9b78b4d503bfe733db1e3f6cdc2b7971ee739626c97e86a558';

    const message = {
        FromAccountIndex: 1,
        ToAccountIndex: 1,
        ToAccountNameHash: hash,
        AssetId: 1,
        packedAmount: 1,
        GasAccountIndex: 1,
        GasFeeAssetId: 1,
        packedFee: 1,
        CallDataHash: chash,
        ExpiredAt: 1,
        Nonce: 1,
        ChainId: 1,
        AssetAmount: hash16,
        ToAddress: hash20,
        GasFeeAssetAmount: 1,
        PairIndex: 1,
        AssetAAmount: 1,
        AssetBAmount: 1,
        AssetAMinAmount: 1,
        AssetBMinAmount: 1,
        LpAmount: 1,
        AccountIndex: 1,
        NftIndex: 1,
        CreatorAccountIndex: 1,
        NftContentHash: chash,
        NftCollectionId: 1,
        CreatorTreasuryRate: 1,
        OfferId: 1,
        sellerAccountIndex: 1,
        sellerNftIndex: 1,
        sellerOfferId: 1,
        sellerType: 1,
        sellerAssetId: 1,
        sellerAssetAmount: 1,
        sellerListedAt: 1,
        sellerExpiredAt: 1,
        sellerSigR: chash,
        sellerSigS: chash,
        buyerAccountIndex: 1,
        buyerNftIndex: 1,
        buyerOfferId: 1,
        buyerType: 1,
        buyerAssetId: 1,
        buyerAssetAmount: 1,
        buyerListedAt: 1,
        buyerExpiredAt: 1,
        buyerSigR: chash,
        buyerSigS: chash,
        sellerTreasureRate: 1,
        buyerTreasureRate: 1
    };
    const domain = {
        name: 'ZKBAS',
        version: '1.0',
        chainId: 10,
        verifyingContract: '',
        salt: salt,
    };

    const data = { types, primaryType, domain, message }
    console.log(ethSignUtl.signTypedData({ privateKey, data, version }))

}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });

