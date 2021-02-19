package zksneak_bn128

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
)

func Setup(b int64) (BulletProofSetupParams, error) {
	return bp_bn128.Setup(b)
}

func Prove(statement *ZKSneakStatement, params *BulletProofSetupParams) (proof *ZKSneakProof, err error) {
	proof = new(ZKSneakProof)
	proof.ProveAnonEnc(statement.Relations)
	proof.ProveAnonRange(statement, params)
	proof.ProveEqual(statement.Relations)
	return proof, nil
}

func (proof *ZKSneakProof) Verify() bool {
	return proof.VerifyAnonEnc() && proof.VerifyAnonRange() && proof.VerifyEqual()
}
