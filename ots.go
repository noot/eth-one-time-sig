package ots

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// OTS represents an ECDSA over secp256k1 one-time signature.
// It's one-time because the private key is unknown.
// The "signature" was generated given only a message,
// and the public key determined using ecrecover.
// The address, which is returned by using the `ecrecover`
// opcode, is also provided.
type OTS struct {
	Signature [65]byte
	Message   [32]byte
	PublicKey *ecdsa.PublicKey
	Address   common.Address
}

// GenerateOTS generates a one-time signature for the given message.
// It also accepts an optional seed to use to generate the signature with.
func GenerateOTS(sigSeed *[32]byte, msg [32]byte) (*OTS, error) {
	if sigSeed == nil {
		// generate random seed if none is provided
		seed := [32]byte{}
		_, err := rand.Read(seed[:])
		if err != nil {
			return nil, err
		}

		sigSeed = &seed
	}

	// calculate R = k*G
	var R secp256k1.JacobianPoint

	k := sha256.Sum256(append([]byte("k"), sigSeed[:]...))
	ks := new(secp256k1.ModNScalar)
	_ = ks.SetByteSlice(k[:])
	if ks.IsZero() {
		return nil, errors.New("seed results in zero k value")
	}

	secp256k1.ScalarBaseMultNonConst(ks, &R)
	R.ToAffine()
	if R.X.IsZero() {
		return nil, errors.New("seed results in zero R_x value")
	}

	rx := R.X.Bytes()

	// calculate some random s where 1 < s < n
	ss := new(secp256k1.ModNScalar)
	s := sha256.Sum256(append([]byte("s"), sigSeed[:]...))
	_ = ss.SetByteSlice(s[:])
	if ss.IsZero() {
		return nil, errors.New("seed results in zero s value")
	}

	s = ss.Bytes()

	// we don't actually need to set v
	// decide if there's any reason we should?
	var v byte
	if R.Y.IsOdd() {
		v = 1
	}

	if ss.IsOverHalfOrder() {
		ss.Negate()
		s = ss.Bytes()
		v ^= 1
	}

	var sig [65]byte
	copy(sig[0:32], rx[:])
	copy(sig[32:64], s[:])
	sig[64] = v

	// get corresponding public key
	pkb, err := crypto.Ecrecover(msg[:], sig[:])
	if err != nil {
		return nil, err
	}

	pk, err := crypto.UnmarshalPubkey(pkb)
	if err != nil {
		return nil, err
	}

	address := crypto.PubkeyToAddress(*pk)

	return &OTS{
		Signature: sig,
		Message:   msg,
		PublicKey: pk,
		Address:   address,
	}, nil
}

// Verify returns true if the signature is valid, false otherwise.
func (s *OTS) Verify() bool {
	return crypto.VerifySignature(
		crypto.CompressPubkey(s.PublicKey),
		s.Message[:],
		s.Signature[:64],
	)
}
