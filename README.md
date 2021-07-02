# zecrey-crypto

`zecrey-crypto` is the crypto library for Zecrey Protocol. It implements not only basic cryptography algorithms, such as `commitment scheme`, `ECC utils`, `finite field utils`, `ElGamal Encryption`, .etc, but also advanced cryptography algorithms, such as `BulletProofs`, `Twisted ElGamal Encryption`, `basic Sigma Protocols`. What's more, it provides many implementations based on different Elliptic Curves. It also includes the core crypto algorithm of the Zecrey Protocol, such as `ComRangeProof`, `Privacy Proof`, `circuit of Zecrey`. Zecrey is based on the curve which is called `baby jubjub`, so the implementation of `baby jubjub` is the core part.

## Project Structure

```json
├─commitment  // commitment scheme
│  ├─secp256k1
│  │  └─pedersen
│  └─twistededwards
│      └─tebn254
│          └─pedersen // pedersen commitment
├─ecc // ECC utils
│  ├─zbls381 // bls12-381
│  ├─zbn254 // bn254
│  ├─zp256 // secp256k1
│  └─ztwistededwards 
│      └─tebn254 // baby jubjub
├─elgamal // ElGamal Encryption
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
│          ├─elgamal // satisfying homomorphic addition
│          └─twistedElgamal // Twisted ElGamal Encryption
├─ffmath // finite field math utils
├─hash // hash utils
│  └─bn254
│      └─zmimc // only support MiMc
├─rangeProofs // range proofs
│  ├─secp256k1
│  │  └─bulletProofs
│  └─twistededwards
│      └─tebn254
│          ├─bulletProofs // BulletProofs
│          └─commitRange // Commitment Range Proofs
├─sigmaProtocol // basic sigma protocols
│  ├─secp256k1
│  │  ├─binary
│  │  ├─chaum-pedersen
│  │  ├─linear
│  │  ├─okamoto
│  │  └─schnorr
│  └─twistededwards
│      └─tebn254
│          ├─binary // binary proof
│          ├─chaum-pedersen // chaum-pedersen proof
│          ├─linear // linear equation proof
│          ├─okamoto // okamoto proof
│          └─schnorr // schnorr proof
├─util // basic utils for Zecrey
├─wasm // wasm version of Zecrey
└─zecrey // core libs
    ├─circuit // circuit implementation
    │  └─bn254
    │      ├─groth16
    │      ├─plonk
    │      └─std // basic circuits
    └─twistededwards
        └─tebn254
            └─zecrey // zecrey algorithms

```

## Have a try

### Twisted ElGamal Encryption

You can try the Twisted ElGamal Encryption in `elgamal/twistededwards/tebn254/twistedElgamal`.

```go
func TestDecByStartRoutine(t *testing.T) {
    // generate key pair for the user
	sk, pk := GenKeyPair()
    // encryption value
	b := big.NewInt(-24029)
    // random value
	r := curve.RandomValue()
    // max value
	max := int64(100000)
    // encrypt it
	enc, _ := Enc(b, r, pk)
	fmt.Println(sk.String())
	fmt.Println(enc.String())
	elapse := time.Now()
    // decrypt it
	res, err := DecByStart(enc, sk, 0, max)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(time.Since(elapse))
    // assert equal
	assert.Equal(t, res, b, "decryption works correctly")
}
```

### Commitment Range Proofs

You can try the Commitment Range Proof in `rangeProofs/twistededwards/tebn254/commitRange`.

```go
func TestProveAndVerify(t *testing.T) {
    // the value needs to be proved
	b := big.NewInt(4)
    // random value
	r := curve.RandomValue()
	g := curve.H
	h := curve.G
    // T is the commitment of b
	T, _ := pedersen.Commit(b, r, g, h)
	elapse := time.Now()
    // prove the correct range
	proof, err := Prove(b, r, T, g, h, 32)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(time.Since(elapse))
    // verify it
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "ComRangeProof works correctly")
}
```

### Privacy Transfer Proof

You can try the Zecrey Privacy Transfer Proof in `zecrey/twistededwards/tebn254/zecrey/transfer_test.go`. For native version, it will take 40ms to generate the proof and 80ms to verify the proof. For wasm version, it will take 1.8s(700ms in Safari) to generate the proof.

```go
func TestCorrectInfoProve(t *testing.T) {
    // generate the key pair for the user1
	sk1, pk1 := twistedElgamal.GenKeyPair()
    // user1's balance
	b1 := big.NewInt(8)
    // random value
	r1 := curve.RandomValue()
    // generate the key pair for the user2
	_, pk2 := twistedElgamal.GenKeyPair()
    // user2's balance
	b2 := big.NewInt(2)
    // random value
	r2 := curve.RandomValue()
    // generate the key pair for the user3
	_, pk3 := twistedElgamal.GenKeyPair()
    // user3's balance
	b3 := big.NewInt(3)
    // random value
	r3 := curve.RandomValue()
    // encryption of the balance
	b1Enc, err := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
    // create the proof relation
	relation, err := NewPTransferProofRelation(1)
	if err != nil {
		t.Error(err)
	}
    // add statement for user1(sender)
	err = relation.AddStatement(b1Enc, pk1, big.NewInt(-4), sk1)
	if err != nil {
		t.Error(err)
	}
    // add statement for user2(receiver)
	err = relation.AddStatement(b2Enc, pk2, big.NewInt(1), nil)
	if err != nil {
		t.Error(err)
	}
    // add statement for user3(receiver)
	err = relation.AddStatement(b3Enc, pk3, big.NewInt(3), nil)
	if err != nil {
		t.Error(err)
	}
    // prove the transfer works correctly
	transferProof, err := ProvePTransfer(relation)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	elapse = time.Now()
	var proof *PTransferProof
    // try to marshal and unmarshal the proof
	proofBytes, err := json.Marshal(transferProof)
	if err != nil {
		t.Error(err)
	}
	err = json.Unmarshal(proofBytes, &proof)
	if err != nil {
		t.Error(err)
	}
    // verify the proof
	res, err := proof.Verify()
	if err != nil {
		t.Error(err)
	}
	fmt.Println("verify time:", time.Since(elapse))
	assert.Equal(t, res, true, "privacy proof works correctly")
}
```

### Privacy Withdraw Proof

You can try the Zecrey Privacy Withdraw Proof in `zecrey/twistededwards/tebn254/zecrey/withdraw.go`. For native version, it will take 20ms to generate the proof and 30ms to verify the proof. For wasm version, it will take 600ms to generate the proof.

```go
func TestProveWithdraw(t *testing.T) {
    // genereate the key pair for the user
	sk, pk := twistedElgamal.GenKeyPair()
    // user's balance
	b := big.NewInt(8)
    // random value
	r := curve.RandomValue()
    // encrypt the value
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	if err != nil {
		t.Error(err)
	}
    // withdraw amount
	bStar := big.NewInt(-2)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
    // create the withdraw relation
	relation, err := NewWithdrawRelation(bEnc, pk, bStar, sk, 1)
	if err != nil {
		t.Error(err)
	}
    // prove withdraw
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
    // marshal and unmarshal withdraw proof
	proofBytes, err := json.Marshal(withdrawProof)
	if err != nil {
		t.Error(err)
	}
	var proof *WithdrawProof
	err = json.Unmarshal(proofBytes, &proof)
	if err != nil {
		t.Error(err)
	}
    // verify the proof
	res, err := proof.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, res, true, "withdraw proof works correctly")
	if res {
        // get the new balance
		bEnc.CR.Add(bEnc.CR, relation.CRStar)
		decVal, err := twistedElgamal.Dec(bEnc, sk, 100)
		if err != nil {
			t.Error(err)
		}
        // new balance should be 6 = 8 - 2
		assert.Equal(t, decVal.String(), "6", "withdraw works correctly")
	}
}

```

### Privacy Swap Proof

You can try the Zecrey Privacy Swap Proof in `zecrey/twistededwards/tebn254/zecrey/swap.go`.

```go
func TestProveSwap(t *testing.T) {
    // create key pair for user1
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
    // Chain 1 user 1 balance
	bEnc1, err := twistedElgamal.Enc(b1, r1, pk1)
	if err != nil {
		t.Error(err)
	}
    // create keypair for user2
	sk2, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(3)
	r2 := curve.RandomValue()
    // chhain 1 user 2 balance
	bEnc2, err := twistedElgamal.Enc(b2, r2, pk2)
	if err != nil {
		t.Error(err)
	}
    // swap amounts
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
    // swap token ids
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
    // create the first proof for user1
	relationPart1, err := NewSwapRelationPart1(bEnc1, bEnc2, pk1, pk2, bStarFrom, bStarTo, sk1, fromTokenId, toTokenId)
	if err != nil {
		t.Error(err)
	}
	swapProofPart1, err := ProveSwapPart1(relationPart1, true)
	if err != nil {
		t.Error(err)
	}
	part1Res, err := swapProofPart1.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, part1Res, true, "prove swap part works correctly")
    // chain 2 user 2 balance
	b3 := big.NewInt(8)
	r3 := curve.RandomValue()
	bEnc3, err := twistedElgamal.Enc(b3, r3, pk2)
	if err != nil {
		t.Error(err)
	}
    // chain 2 user 1 balance
	b4 := big.NewInt(8)
	r4 := curve.RandomValue()
	bEnc4, err := twistedElgamal.Enc(b4, r4, pk1)
	if err != nil {
		t.Error(err)
	}
    // create relation for user2
	relationPart2, err := NewSwapRelationPart2(bEnc3, bEnc4, pk2, pk1, sk2, fromTokenId, toTokenId, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
    // prove swap
	swapProof, err := ProveSwapPart2(relationPart2, swapProofPart1)
	if err != nil {
		t.Error(err)
	}
	swapProofRes, err := swapProof.Verify()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, swapProofRes, true, "swap proof works correctly")
}

```


## Contributions

This project is licensed under the Apache 2 License - see the [LICENSE](https://github.com/zecrey-labs/zecrey-crypto/LICENSE) file for details

Welcome to make contributions to `zecrey-crypto`. Thanks!

