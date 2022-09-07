package std

type EcdsaPkConstraints struct {
	PkBytes [NbAccountEcdsaPkBytes]Variable
}

func SetPkBytesWitness(pk []byte) EcdsaPkConstraints {
	ecdsaPkBytes := EcdsaPkConstraints{}
	for i := range ecdsaPkBytes.PkBytes {
		ecdsaPkBytes.PkBytes[i] = pk[i]
	}
	return ecdsaPkBytes
}

func (e *EcdsaPkConstraints) checkEmptyWitness(api API, flag Variable) {
	for i := range e.PkBytes {
		IsVariableEqual(api, flag, e.PkBytes[i], 0)
	}
}

func EmptyEcdsaPkConstraints() EcdsaPkConstraints {
	ecdsaPkBytes := EcdsaPkConstraints{}
	for i := range ecdsaPkBytes.PkBytes {
		ecdsaPkBytes.PkBytes[i] = 0
	}
	return ecdsaPkBytes
}

// VerifyEcdsaSig TODO: still cannot verify for ecdsa sig
func VerifyEcdsaSig(flag Variable, api API, hFunc MiMC, hashVal Variable, pk EcdsaPkConstraints, sig EcdsaSignatureConstraints) error {
	return nil
}
