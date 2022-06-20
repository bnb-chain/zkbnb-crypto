# zkbas-crypto

`github.com/bnb-chain/zkbas-crypto` is the crypto library for Zecrey Protocol. It implements not only basic cryptography algorithms, such as `commitment scheme`, `ECC utils`, `finite field utils`, `ElGamal Encryption`, .etc, but also advanced cryptography algorithms, such as `BulletProofs`, `Twisted ElGamal Encryption`, `Sigma Protocols`, `Zecrey Privacy Proofs`. What's more, it provides many implementations based on different Elliptic Curves. It also includes the core crypto algorithm of the Zecrey Protocol, such as `ComRangeProof`, `Privacy Proof`, `circuit of Zecrey`. Zecrey is based on the curve which is called `baby jubjub` or `twisted bn254`, so the implementation of `baby jubjub` is the core part.

## Project Structure

```json
ZECREY-CRYPTO
├─.github
│  ├─ISSUE_TEMPLATE
│  └─workflows
├─accumulators // merkle tree implementation
│  └─merkleTree
├─commitment // commitment scheme
│  ├─secp256k1
│  │  └─pedersen
│  └─twistededwards
│      └─tebn254
│          └─pedersen // perdersen commitment
├─ecc // ellptic curves wrapper
│  ├─zbls381
│  ├─zbn254
│  ├─zp256
│  └─ztwistededwards // twisted edwards curve
│      └─tebn254 // baby jubjub
├─elgamal // elgamal algorithms
│  ├─bls381
│  │  ├─elgamal
│  │  └─twistedElgamal
│  ├─bn254
│  │  ├─elgamal
│  │  └─twistedElgamal
│  ├─secp256k1
│  │  ├─elgamal
│  │  └─twistedElgamal
│  └─twistededwards
│      └─tebn254
│          ├─elgamal
│          └─twistedElgamal
├─ffmath // finite fields utils
├─hash // hash algorithms
│  └─bn254
│      └─zmimc
├─rangeProofs // range proofs
│  ├─secp256k1
│  │  └─bulletProofs // bullet proofs
│  └─twistededwards
│      └─tebn254
│          ├─binaryRange // binary range proofs
│          ├─bulletProofs // bullet proofs
│          ├─commitRange
│          └─ctrange // confidential transaction range proof(core algorithms of zkbas)
├─sigmaProtocol // basic sigma protocols
│  ├─secp256k1
│  │  ├─binary
│  │  ├─chaum-pedersen
│  │  ├─linear
│  │  ├─okamoto
│  │  └─schnorr
│  └─twistededwards
│      └─tebn254
│          ├─binary
│          ├─chaum-pedersen
│          ├─linear
│          ├─okamoto
│          └─schnorr
├─util // common utils
├─wasm // wasm for zkbas algorithms
├─circuit // circuit implementation
│  └─bn254
│      ├─groth16
│      ├─mockAccount
│      ├─plonk
│      ├─solidity
│      ├─std // zkbas algorithms circuit
│      ├─transactions // core circuit
│      └─zsha256
└─twistededwards // zkbas privacy proof implementation
   └─tebn254
      ─zecrey
```

## ZKbas Privacy Proofs

### CTRange Proof

#### Example

`rangeProofs/twistededwards/tebn254/ctrange/ctrange_test.go`:

```go
func TestVerify(t *testing.T) {
	b := int64(5)
	elapse := time.Now()
	_, proof, err := Prove(b, curve.G, curve.H)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("1:", time.Since(elapse))
	proofBytes := proof.Bytes()
	proof2, err := FromBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	elapse = time.Now()
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("2:", time.Since(elapse))
	assert.Equal(t, true, res, "invalid proof")
}
```

### Unlock

#### Example

`twistededwards/tebn254/zero/unlock.go`:

```go
func TestUnlockProof_Verify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	chainId := uint32(0)
	assetId := uint32(0)
	balance := uint64(10)
	deltaAmount := uint64(2)
	b_fee := uint64(100)
	feeEnc, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), pk)
	proof, err := ProveUnlock(
		sk, chainId, assetId, balance, deltaAmount,
		feeEnc,
		b_fee, uint32(1), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("fee enc:", feeEnc.String())
	proofStr := proof.String()
	proof2, err := ParseUnlockProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
```

### Transfer

#### Example

`zero/twistededwards/tebn254/zero/transfer_test.go`:

```go
func TestCorrectInfoProve(t *testing.T) {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := uint64(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(big.NewInt(int64(b1)), r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("sk1:", sk1.String())
	fmt.Println("pk1:", curve.ToString(pk1))
	fmt.Println("pk2:", curve.ToString(pk2))
	fmt.Println("pk3:", curve.ToString(pk3))
	fmt.Println("b1Enc:", b1Enc.String())
	fmt.Println("b2Enc:", b2Enc.String())
	fmt.Println("b3Enc:", b3Enc.String())
	elapse := time.Now()
	fee := uint64(1)
	relation, err := NewTransferProofRelation(1, fee)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b2Enc, pk2, 0, 2, nil)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b1Enc, pk1, b1, -3, sk1)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b3Enc, pk3, 0, 0, nil)
	if err != nil {
		t.Error(err)
	}
	proof, err := ProveTransfer(relation)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	elapse = time.Now()
	proofStr := proof.String()
	proof2, err := ParseTransferProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Error(err)
	}
	fmt.Println("verify time:", time.Since(elapse))
	assert.Equal(t, true, res, "invalid proof")
}

```

### Swap

#### Example

`zero/twistededwards/tebn254/zero/swap_test.go`:

```go
func TestSwapProof2_Verify(t *testing.T) {
	b_u_A := uint64(2000)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1000)
	b_B_Delta := uint64(970)
	MinB_B_Delta := uint64(960)
	b_poolA := uint64(40000)
	b_poolB := uint64(40000)
	feeRate := uint32(30)
	treasuryRate := uint32(10)
	GasFee := uint64(30)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	_, Pk_treasury := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	b_fee := uint64(1000)
	//b_fee := b_u_A
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), Pk_u)
	fmt.Println("sk_u:", sk_u.String())
	fmt.Println("C_u_A:", C_uA.String())
	fmt.Println("pk_u:", curve.ToString(Pk_u))
	fmt.Println("Pk_treasury:", curve.ToString(Pk_treasury))
	fmt.Println("C_u_A:", C_uA.String())
	fmt.Println("C_fee:", C_fee.String())
	relation, err := NewSwapRelation(
		C_uA,
		Pk_u, Pk_treasury,
		assetAId, assetBId,
		b_A_Delta, b_u_A,
		MinB_B_Delta,
		feeRate, treasuryRate,
		sk_u,
		C_fee,
		b_fee, uint32(2), GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveSwap(relation)
	if err != nil {
		t.Fatal(err)
	}
	// set params
	err = proof.AddPoolInfo(Pk_pool, b_B_Delta, b_poolA, b_poolB)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseSwapProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
```

### Add Liquidity

#### Example

`zero/twistededwards/tebn254/zero/addLiquidity_test.go`:

```go
func TestAddLiquidityProof_Verify(t *testing.T) {
	b_uA := uint64(8)
	b_uB := uint64(4)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(1)
	b_Dao_A := uint64(10)
	b_Dao_B := uint64(10)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_uA)), curve.RandomValue(), Pk_u)
	C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_uB)), curve.RandomValue(), Pk_u)
	b_fee := uint64(100)
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), Pk_u)
	GasFeeAssetId := uint32(3)
	GasFee := uint64(10)
	fmt.Println("sk:",sk_u.String())
	fmt.Println("Pk_u:",curve.ToString(Pk_u))
	fmt.Println("Pk_pool:",curve.ToString(Pk_pool))
	fmt.Println("C_u_A:",C_uA.String())
	fmt.Println("C_u_B:",C_uB.String())
	fmt.Println("C_fee:",C_fee.String())
	relation, err := NewAddLiquidityRelation(
		C_uA, C_uB,
		Pk_pool, Pk_u,
		assetAId, assetBId,
		b_uA, b_uB,
		b_A_Delta, b_B_Delta,
		sk_u,
		// fee part
		C_fee, b_fee, GasFeeAssetId, GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveAddLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddPoolInfo(b_Dao_A, b_Dao_B)
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseAddLiquidityProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
```

### Remove Liquidity

#### Example

`zero/twistededwards/tebn254/zero/removeLiquidity_test.go`:

```go
func TestRemoveLiquidityProof_Verify(t *testing.T) {
	//b_u_A := uint64(8)
	//b_u_B := uint64(4)
	B_LP := uint64(100)
	assetAId := uint32(1)
	assetBId := uint32(2)
	B_A_Delta := uint64(10)
	B_B_Delta := uint64(10)
	MinB_A_Delta := uint64(1)
	MinB_B_Delta := uint64(1)
	Delta_LP := uint64(10)
	b_pool_A := uint64(1000)
	b_pool_B := uint64(1000)
	Sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	//C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	//C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	C_u_LP, _ := twistedElgamal.Enc(big.NewInt(int64(B_LP)), curve.RandomValue(), Pk_u)
	// fee
	B_fee := uint64(100)
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(B_fee)), curve.RandomValue(), Pk_u)
	GasFeeAssetId := uint32(1)
	GasFee := uint64(1)
	fmt.Println("Sk_u:", Sk_u.String())
	fmt.Println("Pk_u:", curve.ToString(Pk_u))
	fmt.Println("C_u_LP:", C_u_LP.String())
	fmt.Println("C_fee:", C_fee.String())
	relation, err := NewRemoveLiquidityRelation(
		C_u_LP,
		Pk_u,
		B_LP,
		Delta_LP,
		MinB_A_Delta, MinB_B_Delta,
		assetAId, assetBId,
		Sk_u,
		// fee part
		C_fee, B_fee, GasFeeAssetId, GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveRemoveLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	err = proof.AddPoolInfo(Pk_pool, B_A_Delta, B_B_Delta, b_pool_A, b_pool_B, curve.RandomValue(), curve.RandomValue())
	if err != nil {
		t.Fatal(err)
	}
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseRemoveLiquidityProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}
```

### Withdraw

#### Example

`zero/twistededwards/tebn254/zero/withdraw_test.go`:

```go
func TestProveWithdraw(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	b := uint64(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
	if err != nil {
		t.Error(err)
	}
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	bStar := uint64(2)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
	fmt.Println("benc2:", bEnc2.String())
	addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
	assetId := uint32(1)
	feeAssetId := uint32(2)
	relation, err := NewWithdrawRelation(
		1,
		bEnc,
		pk,
		b, bStar,
		sk,
		assetId, addr,
		bEnc2, b_fee, feeAssetId, fee,
	)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
	proofStr := withdrawProof.String()
	proof, err := ParseWithdrawProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "withdraw proof works correctly")
}
```

## ZkBAS Proofs Circuit

### Account Related Constraints

```go
/*
	AccountConstraints: account constraints
*/
type AccountConstraints struct {
	// account index
	AccountIndex Variable
	// account name
	AccountName Variable
	// account public key
	AccountPk Point
	// account state tree root
	StateRoot Variable
	// assets info for each account per tx
	AssetsInfo [NbAccountAssetsPerAccount]AccountAssetConstraints
	// locked assets info for each account per tx
	LockedAssetInfo AccountAssetLockConstraints
	// liquidity assets info for each account per tx
	LiquidityInfo AccountLiquidityConstraints
	// account assets root
	AccountAssetsRoot Variable
	// account locked assets root
	AccountLockedAssetsRoot Variable
	// account liquidity root
	AccountLiquidityRoot Variable
}

/*
	AccountAssetConstraints: account asset tree related constraints
*/
type AccountAssetConstraints struct {
	// asset id
	AssetId Variable
	// twisted ElGamal Encryption balance
	BalanceEnc ElGamalEncConstraints
}

/*
	AccountAssetLockConstraints: account locked asset tree related constraints
*/
type AccountAssetLockConstraints struct {
	// chain id
	ChainId Variable
	// asset id
	AssetId Variable
	// locked amount
	LockedAmount Variable
}

/*
	AccountAssetLockConstraints: account liquidity asset tree related constraints
*/
type AccountLiquidityConstraints struct {
	// pair index
	PairIndex Variable
	// asset a id
	AssetAId Variable
	// asset b id
	AssetBId Variable
	// asset a balance
	AssetA Variable
	// asset b balance
	AssetB Variable
	// asset a random value
	AssetAR Variable
	// asset b random value
	AssetBR Variable
	// LP twisted ElGamal encryption
	LpEnc ElGamalEncConstraints
}
```

### Tx Related Constraints

```go
type TxConstraints struct {
	// tx type
	TxType Variable
	// deposit info
	DepositTxInfo DepositOrLockTxConstraints
	// lock info
	LockTxInfo DepositOrLockTxConstraints
	// unlock proof
	UnlockProof UnlockProofConstraints
	// transfer proof
	TransferProof TransferProofConstraints
	// swap proof
	SwapProof SwapProofConstraints
	// add liquidity proof
	AddLiquidityProof AddLiquidityProofConstraints
	// remove liquidity proof
	RemoveLiquidityProof RemoveLiquidityProofConstraints
	// withdraw proof
	WithdrawProof WithdrawProofConstraints
	// common verification part
	// range proofs
	RangeProofs [MaxRangeProofCount]CtRangeProofConstraints
	// account root before
	AccountRootBefore Variable
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]AccountConstraints
	// before account merkle proof
	MerkleProofsAccountBefore       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountBefore [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// before account asset lock merkle proof
	MerkleProofsAccountLockedAssetsBefore       [NbAccountsPerTx][LockedAssetMerkleLevels]Variable
	MerkleProofsHelperAccountLockedAssetsBefore [NbAccountsPerTx][LockedAssetMerkleHelperLevels]Variable
	// before account liquidity merkle proof
	MerkleProofsAccountLiquidityBefore       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityBefore [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
	// account root after
	AccountRootAfter Variable
	// account after info, size is 4
	AccountsInfoAfter [NbAccountsPerTx]AccountConstraints
	// after account merkle proof
	MerkleProofsAccountAfter       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountAfter [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
	// after account asset merkle proof
	MerkleProofsAccountAssetsAfter       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsAfter [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// after account asset lock merkle proof
	MerkleProofsAccountLockedAssetsAfter       [NbAccountsPerTx][LockedAssetMerkleLevels]Variable
	MerkleProofsHelperAccountLockedAssetsAfter [NbAccountsPerTx][LockedAssetMerkleHelperLevels]Variable
	// after account liquidity merkle proof
	MerkleProofsAccountLiquidityAfter       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityAfter [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
}
```

### Block Related Constraints

```go
type BlockConstraints struct {
	// public inputs
	OldRoot         Variable `gnark:",public"`
	NewRoot         Variable `gnark:",public"`
	BlockCommitment Variable `gnark:",public"`
	// tx info
	Txs [TxsCountPerBlock]TxConstraints
    // TODO add basic info
}
```


## Contributions

Welcome to make contributions to `github.com/bnb-chain/zkbas-crypto`. Thanks!

