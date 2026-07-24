package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type Credential struct {
	IdentityHash string `json:"identityHash"`
	Slot         uint16 `json:"slot"`
	TID          string `json:"tid"`
	PublicKey    string `json:"publicKey"`
	W            string `json:"w"`
	VerifyHash   string `json:"verifyHash"`
}

type SmartContract struct {
	contractapi.Contract
}

func validateHex(name, value string, bytes int) error {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s is not valid hex: %w", name, err)
	}
	if len(raw) != bytes {
		return fmt.Errorf("%s must be %d bytes, got %d", name, bytes, len(raw))
	}
	return nil
}

func credentialKey(identityHash string, slot uint16) string {
	return "cred:" + identityHash + ":" + strconv.Itoa(int(slot))
}

func tidIndexKey(tid string) string {
	return "tid:" + tid
}

func (s *SmartContract) PutCredential(
	ctx contractapi.TransactionContextInterface,
	identityHash string,
	slot uint16,
	tid string,
	publicKey string,
	w string,
	verifyHash string,
) error {
	if err := validateHex("identityHash", identityHash, 32); err != nil {
		return err
	}
	if err := validateHex("tid", tid, 32); err != nil {
		return err
	}
	if err := validateHex("publicKey", publicKey, 800); err != nil {
		return err
	}
	if err := validateHex("w", w, 32); err != nil {
		return err
	}
	if err := validateHex("verifyHash", verifyHash, 32); err != nil {
		return err
	}

	key := credentialKey(identityHash, slot)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("read existing credential: %w", err)
	}

	credential := Credential{
		IdentityHash: identityHash,
		Slot:         slot,
		TID:          tid,
		PublicKey:    publicKey,
		W:            w,
		VerifyHash:   verifyHash,
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	if len(existing) != 0 {
		var previous Credential
		if err := json.Unmarshal(existing, &previous); err != nil {
			return fmt.Errorf("decode previous credential: %w", err)
		}
		if previous.TID != tid {
			if err := ctx.GetStub().DelState(tidIndexKey(previous.TID)); err != nil {
				return fmt.Errorf("remove old TID index: %w", err)
			}
		}
		if string(existing) == string(encoded) {
			return nil
		}
	}

	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	if err := ctx.GetStub().PutState(tidIndexKey(tid), []byte(key)); err != nil {
		return fmt.Errorf("write TID index: %w", err)
	}
	return nil
}

func (s *SmartContract) QueryByIdentitySlot(
	ctx contractapi.TransactionContextInterface,
	identityHash string,
	slot uint16,
) (*Credential, error) {
	if err := validateHex("identityHash", identityHash, 32); err != nil {
		return nil, err
	}
	data, err := ctx.GetStub().GetState(credentialKey(identityHash, slot))
	if err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("credential not found")
	}
	var credential Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	return &credential, nil
}

func (s *SmartContract) QueryByTemporaryIdentity(
	ctx contractapi.TransactionContextInterface,
	tid string,
) (*Credential, error) {
	if err := validateHex("tid", tid, 32); err != nil {
		return nil, err
	}
	key, err := ctx.GetStub().GetState(tidIndexKey(tid))
	if err != nil {
		return nil, fmt.Errorf("read TID index: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("temporary identity not found")
	}
	data, err := ctx.GetStub().GetState(string(key))
	if err != nil {
		return nil, fmt.Errorf("read indexed credential: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("indexed credential missing")
	}
	var credential Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	return &credential, nil
}

func (s *SmartContract) DeleteCredential(
	ctx contractapi.TransactionContextInterface,
	identityHash string,
	slot uint16,
) error {
	credential, err := s.QueryByIdentitySlot(ctx, identityHash, slot)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().DelState(credentialKey(identityHash, slot)); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if err := ctx.GetStub().DelState(tidIndexKey(credential.TID)); err != nil {
		return fmt.Errorf("delete TID index: %w", err)
	}
	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("create APQE chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("start APQE chaincode: %v", err))
	}
}
