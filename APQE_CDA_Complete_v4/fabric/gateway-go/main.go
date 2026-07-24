package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	gatewayMagic         = 0xA952
	gatewayVersion       = 1
	requestHeaderBytes   = 12
	responseHeaderBytes  = 19
	tagBytes             = 32
	idBytes              = 32
	tidBytes             = 32
	publicKeyBytes       = 800
	wBytes               = 32
	hashBytes            = 32
	recordBytes          = idBytes + tidBytes + publicKeyBytes + wBytes + hashBytes
	maxPacketBytes       = responseHeaderBytes + recordBytes + tagBytes
	opPutCredential      = 1
	opQueryIdentitySlot  = 2
	opQueryTID           = 3
	opPing               = 4
	statusOK             = 0
	statusBadRequest     = 1
	statusNotFound       = 2
	statusFabricError    = 3
	statusAuthentication = 4
)

var labHMACKey = []byte{
	0x7a, 0x0c, 0x9e, 0x51, 0x2b, 0xd8, 0x44, 0xf0,
	0xa1, 0x63, 0x37, 0x8d, 0xe4, 0x05, 0xc9, 0x72,
	0x19, 0xb6, 0x2f, 0xaa, 0x84, 0x33, 0xd1, 0x5c,
	0x68, 0xef, 0x90, 0x47, 0x12, 0xbc, 0x5a, 0x26,
}

type Credential struct {
	IdentityHash string `json:"identityHash"`
	Slot         uint16 `json:"slot"`
	TID          string `json:"tid"`
	PublicKey    string `json:"publicKey"`
	W            string `json:"w"`
	VerifyHash   string `json:"verifyHash"`
}

type request struct {
	op        byte
	requestID uint32
	slot      uint16
	payload   []byte
}

type server struct {
	contract *client.Contract
	udp      *net.UDPConn
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func findPrivateKey(directory string) (*ecdsa.PrivateKey, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if key, ok := parsed.(*ecdsa.PrivateKey); ok {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("no ECDSA private key found in %s", directory)
}

func connectFabric() (*grpc.ClientConn, *client.Gateway, *client.Contract, error) {
	org := env("ORG", "1")
	channelName := env("CHANNEL_NAME", "apqechannel")
	chaincodeName := env("CHAINCODE_NAME", "apqe")

	var mspID, peerEndpoint, peerHost, certPath, keyDirectory, tlsPath string
	switch org {
	case "1":
		mspID = "Org1MSP"
		peerEndpoint = "peer0.org1.example.com:7051"
		peerHost = "peer0.org1.example.com"
		certPath = "/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/cert.pem"
		keyDirectory = "/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"
		tlsPath = "/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
	case "2":
		mspID = "Org2MSP"
		peerEndpoint = "peer0.org2.example.com:9051"
		peerHost = "peer0.org2.example.com"
		certPath = "/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/signcerts/cert.pem"
		keyDirectory = "/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore"
		tlsPath = "/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
	default:
		return nil, nil, nil, fmt.Errorf("ORG must be 1 or 2")
	}

	tlsCertificate, err := readCertificate(tlsPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCertificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, peerHost)
	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial peer: %w", err)
	}

	certificate, err := readCertificate(certPath)
	if err != nil {
		connection.Close()
		return nil, nil, nil, fmt.Errorf("load client certificate: %w", err)
	}
	clientIdentity, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		connection.Close()
		return nil, nil, nil, fmt.Errorf("create identity: %w", err)
	}
	privateKey, err := findPrivateKey(keyDirectory)
	if err != nil {
		connection.Close()
		return nil, nil, nil, fmt.Errorf("load private key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		connection.Close()
		return nil, nil, nil, fmt.Errorf("create signer: %w", err)
	}

	gateway, err := client.Connect(
		clientIdentity,
		client.WithSign(sign),
		client.WithClientConnection(connection),
		client.WithEvaluateTimeout(10*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(10*time.Second),
		client.WithCommitStatusTimeout(60*time.Second),
	)
	if err != nil {
		connection.Close()
		return nil, nil, nil, fmt.Errorf("connect Fabric gateway: %w", err)
	}
	contract := gateway.GetNetwork(channelName).GetContract(chaincodeName)
	return connection, gateway, contract, nil
}

func authenticate(data, tag []byte) bool {
	mac := hmac.New(sha256.New, labHMACKey)
	_, _ = mac.Write(data)
	return hmac.Equal(mac.Sum(nil), tag)
}

func parseRequest(packet []byte) (*request, byte, error) {
	if len(packet) < requestHeaderBytes+tagBytes {
		return nil, statusBadRequest, errors.New("packet too short")
	}
	if binary.BigEndian.Uint16(packet[0:2]) != gatewayMagic || packet[2] != gatewayVersion {
		return nil, statusBadRequest, errors.New("bad magic or version")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[10:12]))
	expectedLength := requestHeaderBytes + payloadLength + tagBytes
	if expectedLength != len(packet) {
		return nil, statusBadRequest, fmt.Errorf("length mismatch")
	}
	if !authenticate(packet[:requestHeaderBytes+payloadLength], packet[requestHeaderBytes+payloadLength:]) {
		return nil, statusAuthentication, errors.New("HMAC verification failed")
	}
	return &request{
		op:        packet[3],
		requestID: binary.BigEndian.Uint32(packet[4:8]),
		slot:      binary.BigEndian.Uint16(packet[8:10]),
		payload:   packet[12 : 12+payloadLength],
	}, statusOK, nil
}

func buildResponse(op byte, requestID uint32, status byte, fabricUS uint64, payload []byte) []byte {
	response := make([]byte, responseHeaderBytes+len(payload)+tagBytes)
	binary.BigEndian.PutUint16(response[0:2], gatewayMagic)
	response[2] = gatewayVersion
	response[3] = op | 0x80
	binary.BigEndian.PutUint32(response[4:8], requestID)
	response[8] = status
	binary.BigEndian.PutUint64(response[9:17], fabricUS)
	binary.BigEndian.PutUint16(response[17:19], uint16(len(payload)))
	copy(response[19:], payload)
	mac := hmac.New(sha256.New, labHMACKey)
	_, _ = mac.Write(response[:responseHeaderBytes+len(payload)])
	copy(response[responseHeaderBytes+len(payload):], mac.Sum(nil))
	return response
}

func credentialFromPayload(payload []byte, slot uint16) (*Credential, error) {
	if len(payload) != recordBytes {
		return nil, fmt.Errorf("credential payload must be %d bytes", recordBytes)
	}
	offset := 0
	identityHash := hex.EncodeToString(payload[offset : offset+idBytes])
	offset += idBytes
	tid := hex.EncodeToString(payload[offset : offset+tidBytes])
	offset += tidBytes
	publicKey := hex.EncodeToString(payload[offset : offset+publicKeyBytes])
	offset += publicKeyBytes
	w := hex.EncodeToString(payload[offset : offset+wBytes])
	offset += wBytes
	verifyHash := hex.EncodeToString(payload[offset : offset+hashBytes])
	return &Credential{
		IdentityHash: identityHash,
		Slot:         slot,
		TID:          tid,
		PublicKey:    publicKey,
		W:            w,
		VerifyHash:   verifyHash,
	}, nil
}

func credentialPayload(credential *Credential) ([]byte, error) {
	fields := []struct {
		name  string
		value string
		size  int
	}{
		{"identityHash", credential.IdentityHash, idBytes},
		{"tid", credential.TID, tidBytes},
		{"publicKey", credential.PublicKey, publicKeyBytes},
		{"w", credential.W, wBytes},
		{"verifyHash", credential.VerifyHash, hashBytes},
	}
	output := make([]byte, 0, recordBytes)
	for _, field := range fields {
		decoded, err := hex.DecodeString(field.value)
		if err != nil || len(decoded) != field.size {
			return nil, fmt.Errorf("invalid %s in ledger response", field.name)
		}
		output = append(output, decoded...)
	}
	return output, nil
}

func sameCredential(a, b *Credential) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IdentityHash == b.IdentityHash && a.Slot == b.Slot &&
		a.TID == b.TID && a.PublicKey == b.PublicKey &&
		a.W == b.W && a.VerifyHash == b.VerifyHash
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not found") || strings.Contains(text, "missing")
}

func (s *server) evaluateCredential(function string, args ...string) (*Credential, uint64, error) {
	start := time.Now()
	data, err := s.contract.EvaluateTransaction(function, args...)
	elapsed := uint64(time.Since(start).Microseconds())
	if err != nil {
		return nil, elapsed, err
	}
	var credential Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return nil, elapsed, err
	}
	return &credential, elapsed, nil
}

func (s *server) handle(req *request) (byte, uint64, []byte, error) {
	switch req.op {
	case opPing:
		return statusOK, 0, nil, nil

	case opPutCredential:
		credential, err := credentialFromPayload(req.payload, req.slot)
		if err != nil {
			return statusBadRequest, 0, nil, err
		}
		existing, evalUS, queryErr := s.evaluateCredential(
			"QueryByIdentitySlot", credential.IdentityHash, strconv.Itoa(int(req.slot)))
		if queryErr == nil && sameCredential(existing, credential) {
			return statusOK, evalUS, nil, nil
		}
		start := time.Now()
		_, err = s.contract.SubmitTransaction(
			"PutCredential",
			credential.IdentityHash,
			strconv.Itoa(int(req.slot)),
			credential.TID,
			credential.PublicKey,
			credential.W,
			credential.VerifyHash,
		)
		elapsed := uint64(time.Since(start).Microseconds())
		if err != nil {
			return statusFabricError, elapsed, nil, err
		}
		return statusOK, elapsed, nil, nil

	case opQueryIdentitySlot:
		if len(req.payload) != idBytes {
			return statusBadRequest, 0, nil, fmt.Errorf("identity query payload must be %d bytes", idBytes)
		}
		credential, elapsed, err := s.evaluateCredential(
			"QueryByIdentitySlot",
			hex.EncodeToString(req.payload),
			strconv.Itoa(int(req.slot)),
		)
		if err != nil {
			if isNotFound(err) {
				return statusNotFound, elapsed, nil, err
			}
			return statusFabricError, elapsed, nil, err
		}
		payload, err := credentialPayload(credential)
		if err != nil {
			return statusFabricError, elapsed, nil, err
		}
		return statusOK, elapsed, payload, nil

	case opQueryTID:
		if len(req.payload) != tidBytes {
			return statusBadRequest, 0, nil, fmt.Errorf("TID query payload must be %d bytes", tidBytes)
		}
		credential, elapsed, err := s.evaluateCredential(
			"QueryByTemporaryIdentity",
			hex.EncodeToString(req.payload),
		)
		if err != nil {
			if isNotFound(err) {
				return statusNotFound, elapsed, nil, err
			}
			return statusFabricError, elapsed, nil, err
		}
		payload, err := credentialPayload(credential)
		if err != nil {
			return statusFabricError, elapsed, nil, err
		}
		return statusOK, elapsed, payload, nil

	default:
		return statusBadRequest, 0, nil, fmt.Errorf("unknown operation %d", req.op)
	}
}

func (s *server) serve(ctx context.Context) error {
	buffer := make([]byte, maxPacketBytes)
	for {
		if err := s.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		length, remote, err := s.udp.ReadFromUDP(buffer)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return err
		}

		packet := append([]byte(nil), buffer[:length]...)
		req, parseStatus, parseErr := parseRequest(packet)
		if parseErr != nil {
			log.Printf("reject from %s: %v", remote, parseErr)
			if req != nil {
				response := buildResponse(req.op, req.requestID, parseStatus, 0, nil)
				_, _ = s.udp.WriteToUDP(response, remote)
			}
			continue
		}

		status, fabricUS, payload, handleErr := s.handle(req)
		if handleErr != nil {
			log.Printf("op=%d request=%d from=%s status=%d error=%v",
				req.op, req.requestID, remote, status, handleErr)
		} else {
			log.Printf("op=%d request=%d from=%s status=%d fabric_us=%d payload=%d",
				req.op, req.requestID, remote, status, fabricUS, len(payload))
		}
		response := buildResponse(req.op, req.requestID, status, fabricUS, payload)
		for copyIndex := 0; copyIndex < 3; copyIndex++ {
			_, _ = s.udp.WriteToUDP(response, remote)
			if copyIndex != 2 {
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
}

func main() {
	connection, gateway, contract, err := connectFabric()
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	defer gateway.Close()

	port := env("UDP_PORT", "5002")
	address, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()

	log.Printf("APQE Fabric gateway listening on UDP %s, ORG=%s", port, env("ORG", "1"))
	srv := &server{contract: contract, udp: udp}
	if err := srv.serve(context.Background()); err != nil {
		log.Fatal(err)
	}
}
