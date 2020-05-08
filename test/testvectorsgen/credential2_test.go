package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/iden3/go-circom-prover-verifier/parsers"
	zktypes "github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-iden3-core/components/idenpuboffchain"
	idenpuboffchanlocal "github.com/iden3/go-iden3-core/components/idenpuboffchain/local"
	"github.com/iden3/go-iden3-core/components/idenpubonchain"
	idenpubonchainlocal "github.com/iden3/go-iden3-core/components/idenpubonchain/local"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/identity/holder"
	"github.com/iden3/go-iden3-core/identity/issuer"
	"github.com/iden3/go-iden3-core/keystore"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	log "github.com/sirupsen/logrus"
)

var blockN uint64
var blockTs int64

var idenPubOffChain *idenpuboffchanlocal.IdenPubOffChain
var idenPubOnChain *idenpubonchainlocal.IdenPubOnChain
var idenStateZkProofConf *issuer.IdenStateZkProofConf

var pass = []byte("my passphrase")

const idOwnershipLevels = 16
const issuerLevels = 16

type Inputs struct {
	// A
	Claim [8]*big.Int `json:"claim"`

	// B. holder proof of claimKOp in the genesis
	HoKOpSk                  *big.Int   `json:"hoKOpSk"`
	HoClaimKOpMtp            []*big.Int `json:"hoClaimKOpMtp"`
	HoClaimKOpClaimsTreeRoot *big.Int   `json:"hoClaimKOpClaimsTreeRoot"`
	// HoClaimKOpRevTreeRoot    *big.Int   `json:"hoClaimKOpRevTreeRoot"`
	// HoClaimKOpRootsTreeRoot  *big.Int   `json:"hoClaimKOpRootsTreeRoot"`

	// C. issuer proof of claim existence
	IsProofExistMtp            []*big.Int `json:"isProofExistMtp"`
	IsProofExistClaimsTreeRoot *big.Int   `json:"isProofExistClaimsTreeRoot"`
	// signal input isProofExistRevTreeRoot;
	// signal input isProofExistRootsTreeRoot;

	// D. issuer proof of claim validity
	IsProofValidMtp            []*big.Int `json:"isProofValidMtp"`
	IsProofValidClaimsTreeRoot *big.Int   `json:"isProofValidClaimsTreeRoot"`
	IsProofValidRevTreeRoot    *big.Int   `json:"isProofValidRevTreeRoot"`
	IsProofValidRootsTreeRoot  *big.Int   `json:"isProofValidRootsTreeRoot"`

	// E. issuer proof of Root (ExistClaimsTreeRoot)
	IsProofRootMtp []*big.Int `json:"isProofRootMtp"`

	// F. issuer recent idenState
	IsIdenState *big.Int `json:"isIdenState"`
}

// func Copy(dst interface{}, src interface{}) {
// 	srcJSON, err := json.Marshal(src)
// 	if err != nil {
// 		panic(err)
// 	}
// 	if err := json.Unmarshal(srcJSON, dst); err != nil {
// 		panic(err)
// 	}
// }

func newIssuer(t *testing.T, idenPubOnChain idenpubonchain.IdenPubOnChainer,
	idenPubOffChainWrite idenpuboffchain.IdenPubOffChainWriter) (*issuer.Issuer, db.Storage, *keystore.KeyStore) {
	cfg := issuer.ConfigDefault
	storage := db.NewMemoryStorage()
	ksStorage := keystore.MemStorage([]byte{})
	keyStore, err := keystore.NewKeyStore(&ksStorage, keystore.LightKeyStoreParams)
	require.Nil(t, err)
	// kOp, err := keyStore.NewKey(pass)
	var sk babyjub.PrivateKey
	sk[0] = 0x11
	kOp, err := keyStore.ImportKey(sk, pass)
	require.Nil(t, err)
	err = keyStore.UnlockKey(kOp, pass)
	require.Nil(t, err)
	_, err = issuer.Create(cfg, kOp, []claims.Claimer{}, storage, keyStore)
	require.Nil(t, err)
	is, err := issuer.Load(storage, keyStore, idenPubOnChain, idenStateZkProofConf, idenPubOffChainWrite)
	require.Nil(t, err)
	return is, storage, keyStore
}

func newHolder(t *testing.T, idenPubOnChain idenpubonchain.IdenPubOnChainer,
	idenPubOffChainWrite idenpuboffchain.IdenPubOffChainWriter,
	idenPubOffChainRead idenpuboffchain.IdenPubOffChainReader) (*holder.Holder, db.Storage, *keystore.KeyStore) {
	cfg := holder.ConfigDefault
	storage := db.NewMemoryStorage()
	ksStorage := keystore.MemStorage([]byte{})
	keyStore, err := keystore.NewKeyStore(&ksStorage, keystore.LightKeyStoreParams)
	require.Nil(t, err)
	// kOp, err := keyStore.NewKey(pass)
	var sk babyjub.PrivateKey
	sk[0] = 0x22
	kOp, err := keyStore.ImportKey(sk, pass)
	require.Nil(t, err)
	err = keyStore.UnlockKey(kOp, pass)
	require.Nil(t, err)
	_, err = holder.Create(cfg, kOp, []claims.Claimer{}, storage, keyStore)
	require.Nil(t, err)
	ho, err := holder.Load(storage, keyStore, idenPubOnChain, idenStateZkProofConf,
		idenPubOffChainWrite, idenPubOffChainRead)
	require.Nil(t, err)
	return ho, storage, keyStore
}

func TestVerifyCredentialValidity(t *testing.T) {
	// verifier := verifier.NewWithTimeNow(idenPubOnChain, func() time.Time {
	// 	return time.Unix(blockTs, 0)
	// })

	ho, _, _ := newHolder(t, idenPubOnChain, nil, idenPubOffChain)

	//
	// {Ts: 1000, BlockN: 120} -> claim1 is added
	//
	blockTs, blockN = 1000, 120

	// ISSUER: Publish state first time with claim1

	indexBytes, valueBytes := [claims.IndexSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	indexBytes[0] = 0x42
	claim1 := claims.NewClaimBasic(indexBytes, valueBytes)

	is, _, _ := newIssuer(t, idenPubOnChain, idenPubOffChain)
	err := is.IssueClaim(claim1)
	require.Nil(t, err)

	// Publishing state for the first time
	err = is.PublishState()
	require.Nil(t, err)
	idenPubOnChain.Sync()

	blockTs += 20
	blockN += 10

	err = is.SyncIdenStatePublic()
	require.Nil(t, err)

	credExistClaim1, err := is.GenCredentialExistence(claim1)
	require.Nil(t, err)

	// HOLDER + VERIFIER

	// credValidClaim1t1, err := ho.HolderGetCredentialValidity(credExistClaim1)
	// require.Nil(t, err)

	//
	// {Ts: 2000, BlockN: 130} -> claim2 is added
	//
	blockTs, blockN = 2000, 130

	// ISSUER: Publish state a second time with another claim2, claim3

	indexBytes, valueBytes = [claims.IndexSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	indexBytes[0] = 0x48
	claim2 := claims.NewClaimBasic(indexBytes, valueBytes)

	err = is.IssueClaim(claim2)
	require.Nil(t, err)

	// claim3 is a claim with expiration at T=3500

	header := claims.ClaimHeader{
		Type:       claims.NewClaimTypeNum(9999),
		Subject:    claims.ClaimSubjectSelf,
		Expiration: true,
		Version:    false,
	}
	metadata := claims.NewMetadata(header)
	metadata.Expiration = 3500
	var entry merkletree.Entry
	metadata.Marshal(&entry)
	claim3 := claims.NewClaimGeneric(&entry)

	err = is.IssueClaim(claim3)
	require.Nil(t, err)

	err = is.PublishState()
	require.Nil(t, err)
	idenPubOnChain.Sync()

	err = is.SyncIdenStatePublic()
	require.Nil(t, err)

	// credExistClaim2, err := is.GenCredentialExistence(claim2)
	// require.Nil(t, err)

	// HOLDER + VERIFIER

	credValid, err := ho.HolderGetCredentialValidity(credExistClaim1)
	assert.Nil(t, err)
	assert.NotNil(t, credValid)

	// credValidJSON, err := json.MarshalIndent(credValid, "", "  ")
	// assert.Nil(t, err)
	// fmt.Printf("%v\n", string(credValidJSON))

	var inputs Inputs

	idOwnershipInputs, err := is.GenIdOwnershipGenesisInputs()
	require.Nil(t, err)

	inputs.HoKOpSk = idOwnershipInputs.PrivateKey
	inputs.HoClaimKOpMtp = idOwnershipInputs.MtpSiblings
	inputs.HoClaimKOpClaimsTreeRoot = idOwnershipInputs.ClaimsTreeRoot

	for i, elem := range credValid.CredentialExistence.Claim.Data {
		inputs.Claim[i] = elem.BigInt()
	}
	inputs.IsProofValidClaimsTreeRoot = credValid.ClaimsTreeRoot.BigInt()
	inputs.IsProofValidRootsTreeRoot = credValid.RootsTreeRoot.BigInt()

	inputs.IsProofValidMtp = credValid.CredentialExistence.MtpClaim.AllSiblingsCircom(issuerLevels)
	inputs.IsProofExistMtp = credValid.MtpNotNonce.AllSiblingsCircom(issuerLevels)

	inputs.IsIdenState = credValid.IdenStateData.IdenState.BigInt()

	inputsJSON, err := json.MarshalIndent(inputs, "", "  ")
	assert.Nil(t, err)
	fmt.Printf("%v\n", string(inputsJSON))
}

var _vk *zktypes.Vk

func TestMain(m *testing.M) {
	log.SetLevel(log.DebugLevel)
	downloadPath := "/tmp/iden3/idenstatezk"
	err := issuer.GetIdenStateZKFiles("http://161.35.72.58:9000/circuit-idstate/", downloadPath)
	if err != nil {
		panic(err)
	}
	vkJSON, err := ioutil.ReadFile(path.Join(downloadPath, "verification_key.json"))
	if err != nil {
		panic(err)
	}
	vk, err := parsers.ParseVk(vkJSON)
	if err != nil {
		panic(err)
	}
	_vk = vk
	idenPubOnChain = idenpubonchainlocal.New(
		func() time.Time {
			return time.Unix(blockTs, 0)
		},
		func() uint64 {
			return blockN
		},
		vk,
	)
	idenPubOffChain = idenpuboffchanlocal.NewIdenPubOffChain("http://foo.bar")
	idenStateZkProofConf = &issuer.IdenStateZkProofConf{
		Levels:              16,
		PathWitnessCalcWASM: path.Join(downloadPath, "circuit.wasm"),
		PathProvingKey:      path.Join(downloadPath, "proving_key.json"),
		PathVerifyingKey:    path.Join(downloadPath, "verification_key.json"),
		CacheProvingKey:     true,
	}
	os.Exit(m.Run())
}
