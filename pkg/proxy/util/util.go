package util

import (
	"bufio"
	"crypto"
	"sync"

	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"time"

	"path/filepath"

	"go.uber.org/zap"

	// "math/rand"
	"net"
	"strconv"
	"strings"
	"unicode"

	cfsslLog "github.com/cloudflare/cfssl/log"

	"github.com/agnivade/levenshtein"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"

	"go.keploy.io/server/pkg"
	"go.keploy.io/server/pkg/hooks"
	"go.keploy.io/server/pkg/hooks/structs"
	"go.keploy.io/server/pkg/models"
	"go.keploy.io/server/utils"
)

var mu sync.Mutex

type certKeyPair struct {
	cert tls.Certificate
	host string
}

var (
	caPrivKey      interface{}
	caCertParsed   *x509.Certificate
	destinationUrl string
	SourceDestInfo = make(map[int]*structs.DestInfo)
)

var Emoji = "\U0001F430" + " Keploy:"

var sendLogs = true

//go:embed asset/ca.crt
var CaCrt []byte

//go:embed asset/ca.key
var CaPKey []byte

//go:embed asset
var CaFolder embed.FS

type Connection struct {
	ClientConnection *net.Conn
	DestConnection   *net.Conn
	IsClient         bool
}
type CustomConn struct {
	net.Conn
	r      io.Reader
	logger *zap.Logger
}

func (c *CustomConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		c.logger.Debug("the length is 0 for the reading from customConn")
	}
	return c.r.Read(p)
}
func ReadBuffConn(conn Connection, bufferChannel chan []byte, errChannel chan error, logger *zap.Logger) error {
	for {
		if (conn.IsClient && conn.ClientConnection == nil) || (!conn.IsClient && conn.DestConnection == nil) {
			logger.Debug("the connection is nil")
		}
		buffer, err := ReadBytes(&conn)
		if err != nil {
			logger.Error("failed to read the packet message in proxy for generic dependency", zap.Error(err))
			errChannel <- err
			return err
		}
		bufferChannel <- buffer
		break
	}
	return nil
}

func ValidatePath(path string) (string, error) {
	// Validate the input to prevent directory traversal attack
	if strings.Contains(path, "..") {
		return "", errors.New("invalid path: contains '..' indicating directory traversal")
	}
	return path, nil
}

// createYamlFile is used to create the yaml file along with the path directory (if does not exists)
func CreateYamlFile(path string, fileName string, Logger *zap.Logger) (bool, error) {
	// checks id the yaml exists
	yamlPath, err := ValidatePath(filepath.Join(path, fileName+".yaml"))
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(yamlPath); err != nil {
		// creates the path director if does not exists
		err = os.MkdirAll(filepath.Join(path), fs.ModePerm)
		if err != nil {
			Logger.Error("failed to create a directory for the yaml file", zap.Error(err), zap.Any("path directory", path), zap.Any("yaml", fileName))
			return false, err
		}

		// create the yaml file
		_, err := os.Create(yamlPath)
		if err != nil {
			Logger.Error("failed to create a yaml file", zap.Error(err), zap.Any("path directory", path), zap.Any("yaml", fileName))
			return false, err
		}

		// since, keploy requires root access. The permissions for generated files
		// should be updated to share it with all users.
		keployPath := path
		if strings.Contains(path, "keploy/"+models.TestSetPattern) {
			keployPath = filepath.Join(strings.TrimSuffix(path, filepath.Base(path)))
		}
		Logger.Debug("the path to the generated keploy directory", zap.Any("path", keployPath))
		cmd := exec.Command("sudo", "chmod", "-R", "777", keployPath)
		err = cmd.Run()
		if err != nil {
			Logger.Error("failed to set the permission of keploy directory", zap.Error(err))
			return false, err
		}

		return true, nil
	}
	return false, nil
}

func Passthrough(clientConn, destConn net.Conn, requestBuffer [][]byte, recover func(id int), logger *zap.Logger) ([]byte, error) {

	if destConn == nil {
		return nil, errors.New("failed to pass network traffic to the destination connection")
	}
	logger.Debug("trying to forward requests to target", zap.Any("Destination Addr", destConn.RemoteAddr().String()))
	for _, v := range requestBuffer {
		_, err := destConn.Write(v)
		if err != nil {
			logger.Error("failed to write request message to the destination server", zap.Error(err), zap.Any("Destination Addr", destConn.RemoteAddr().String()))
			return nil, err
		}
	}
	// defer destConn.Close()

	// channels for writing messages from proxy to destination or client
	destBufferChannel := make(chan []byte)
	errChannel := make(chan error)

	go func() {
		// Recover from panic and gracefully shutdown
		defer recover(pkg.GenerateRandomID())
		defer utils.HandlePanic()
		conn := Connection{
			ClientConnection: &clientConn,
			DestConnection:   &destConn,
			IsClient:         false,
		}
		ReadBuffConn(conn, destBufferChannel, errChannel, logger)
	}()

	select {
	case buffer := <-destBufferChannel:
		// Write the response message to the client
		_, err := clientConn.Write(buffer)
		if err != nil {
			logger.Error("failed to write response to the client", zap.Error(err))
			return nil, err
		}

		logger.Debug("the iteration for the generic response ends with responses:"+strconv.Itoa(len(buffer)), zap.Any("buffer", buffer))
	case err := <-errChannel:
		if netErr, ok := err.(net.Error); !(ok && netErr.Timeout()) && err != nil {
			return nil, err
		}
		return nil, nil
	}

	// }

	return nil, nil
}

// ToIP4AddressStr converts the integer IP4 Address to the octet format
func ToIP4AddressStr(ip uint32) string {
	// convert the IP address to a 32-bit binary number
	ipBinary := fmt.Sprintf("%032b", ip)

	// divide the binary number into four 8-bit segments
	firstByte, _ := strconv.ParseUint(ipBinary[0:8], 2, 64)
	secondByte, _ := strconv.ParseUint(ipBinary[8:16], 2, 64)
	thirdByte, _ := strconv.ParseUint(ipBinary[16:24], 2, 64)
	fourthByte, _ := strconv.ParseUint(ipBinary[24:32], 2, 64)

	// concatenate the four decimal segments with a dot separator to form the dot-decimal string
	return fmt.Sprintf("%d.%d.%d.%d", firstByte, secondByte, thirdByte, fourthByte)
}

func ToIPv6AddressStr(ip [4]uint32) string {
	// construct a byte slice
	ipBytes := make([]byte, 16) // IPv6 address is 128 bits or 16 bytes long
	for i := 0; i < 4; i++ {
		// for each uint32, extract its four bytes and put them into the byte slice
		ipBytes[i*4] = byte(ip[i] >> 24)
		ipBytes[i*4+1] = byte(ip[i] >> 16)
		ipBytes[i*4+2] = byte(ip[i] >> 8)
		ipBytes[i*4+3] = byte(ip[i])
	}
	// net.IP is a byte slice, so it can be directly used to construct an IPv6 address
	ipv6Addr := net.IP(ipBytes)
	return ipv6Addr.String()
}

func PeekBytes(reader *bufio.Reader) ([]byte, error) {
	var buffer []byte

	buf := make([]byte, 1024)

	// Read bytes from the Reader
	reader.Peek(1)
	buf, err := reader.Peek(reader.Buffered())
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return nil, err
	}

	// Append the bytes to the buffer
	buffer = append(buffer, buf[:]...)

	return buffer, nil
}

// ReadBytes function is utilized to read the complete message from the reader until the end of the file (EOF).
// It returns the content as a byte array.
func ReadBytes(reader *Connection) ([]byte, error) {
	var buffer []byte
	const maxEmptyReads = 5
	emptyReads := 0
	var connReader *bufio.Reader
	if reader.IsClient {
		connReader = bufio.NewReader(*reader.ClientConnection)
		fmt.Println("read it client")
	} else {
		connReader = bufio.NewReader(*reader.DestConnection)
		fmt.Println("read it destination")
	}
	if reader.IsClient {
		initialData := make([]byte, 5)
		testBuffer, err := connReader.Peek(len(initialData))
		fmt.Println("testBuffer", string(testBuffer), err)
		isTLS := isTLSHandshake(testBuffer)
		if isTLS {
			mu.Lock()
			defer mu.Unlock()
			multiReader := io.MultiReader(connReader, *reader.ClientConnection)
			*reader.ClientConnection = &CustomConn{
				Conn: *reader.ClientConnection,
				r:    multiReader,
			}
			tlsConnection, err := HandleTLSConnection(*reader.ClientConnection)
			fmt.Println("tlsConnection", err)
			connReader = bufio.NewReader(tlsConnection)
			reader.ClientConnection = &tlsConnection
			config := &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         destinationUrl,
			}
			var dst net.Conn
			remoteAddr := (*reader.ClientConnection).RemoteAddr().(*net.TCPAddr)
			sourcePort := remoteAddr.Port
			dst, err = tls.Dial("tcp", fmt.Sprintf("%v:%v", destinationUrl, SourceDestInfo[sourcePort].DestPort), config)
			fmt.Println("dst", err)
			reader.DestConnection = &dst
			fmt.Println("twist of fate happened", sourcePort)
		}
	}
	for {
		buf := make([]byte, 1024)

		n, err := connReader.Read(buf)
		fmt.Println(string(buf), "bufer")
		if n > 0 {
			buffer = append(buffer, buf[:n]...)
			emptyReads = 0 // reset the counter because we got some data
		}

		if err != nil {
			if err == io.EOF {
				emptyReads++
				if emptyReads >= maxEmptyReads {
					fmt.Println(err.Error(), "eof hai bhaiya")
					return buffer, err // multiple EOFs in a row, probably a true EOF
				}
				time.Sleep(time.Millisecond * 100) // sleep before trying again
				continue
			}
			fmt.Println(err.Error(), "error hai bhaiya")

			return buffer, err
		}

		if n < len(buf) {
			break
		}
	}

	return buffer, nil

}

func GetLocalIPv4() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				return ipNet.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("No valid IP address found")
}

func ConvertToIPV4(ip net.IP) (uint32, bool) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, false // Return 0 or handle the error accordingly
	}

	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), true
}

func GetLocalIPv6() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() == nil && ipNet.IP.To16() != nil {
				return ipNet.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("No valid IPv6 address found")
}

func ConvertIPv6ToUint32Array(ip net.IP) ([4]uint32, error) {
	ip = ip.To16()
	if ip == nil {
		return [4]uint32{}, errors.New("invalid IPv6 address")
	}

	return [4]uint32{
		binary.BigEndian.Uint32(ip[0:4]),
		binary.BigEndian.Uint32(ip[4:8]),
		binary.BigEndian.Uint32(ip[8:12]),
		binary.BigEndian.Uint32(ip[12:16]),
	}, nil
}

func IPToDotDecimal(ip net.IP) string {
	ipStr := ip.String()
	if ip.To4() != nil {
		ipStr = ip.To4().String()
	}
	return ipStr
}

// It checks if the cmd is related to docker or not, it also returns if its a docker compose file
func IsDockerRelatedCommand(cmd string) (bool, string) {
	// Check for Docker command patterns
	dockerCommandPatterns := []string{
		"docker-compose ",
		"sudo docker-compose ",
		"docker compose ",
		"sudo docker compose ",
		"docker ",
		"sudo docker ",
	}

	for _, pattern := range dockerCommandPatterns {
		if strings.HasPrefix(strings.ToLower(cmd), pattern) {
			if strings.Contains(pattern, "compose") {
				return true, "docker-compose"
			}
			return true, "docker"
		}
	}

	// Check for Docker Compose file extension
	dockerComposeFileExtensions := []string{".yaml", ".yml"}
	for _, extension := range dockerComposeFileExtensions {
		if strings.HasSuffix(strings.ToLower(cmd), extension) {
			return true, "docker-compose"
		}
	}

	return false, ""
}

func findStringMatch(req string, mockString []string) int {
	minDist := int(^uint(0) >> 1) // Initialize with max int value
	bestMatch := -1
	for idx, req := range mockString {
		if !IsAsciiPrintable(mockString[idx]) {
			continue
		}

		dist := levenshtein.ComputeDistance(req, mockString[idx])
		if dist == 0 {
			return 0
		}

		if dist < minDist {
			minDist = dist
			bestMatch = idx
		}
	}
	return bestMatch
}

func HttpDecoder(encoded string) ([]byte, error) {
	// decode the string to a buffer.

	data := []byte(encoded)
	return data, nil
}

func AdaptiveK(length, kMin, kMax, N int) int {
	k := length / N
	if k < kMin {
		return kMin
	} else if k > kMax {
		return kMax
	}
	return k
}

func CreateShingles(data []byte, k int) map[string]struct{} {
	shingles := make(map[string]struct{})
	for i := 0; i < len(data)-k+1; i++ {
		shingle := string(data[i : i+k])
		shingles[shingle] = struct{}{}
	}
	return shingles
}

// JaccardSimilarity computes the Jaccard similarity between two sets of shingles.
func JaccardSimilarity(setA, setB map[string]struct{}) float64 {
	intersectionSize := 0
	for k := range setA {
		if _, exists := setB[k]; exists {
			intersectionSize++
		}
	}

	unionSize := len(setA) + len(setB) - intersectionSize

	if unionSize == 0 {
		return 0.0
	}
	return float64(intersectionSize) / float64(unionSize)
}

func findBinaryMatch(configMocks []*models.Mock, reqBuff []byte, h *hooks.Hook) int {

	mxSim := -1.0
	mxIdx := -1
	// find the fuzzy hash of the mocks
	for idx, mock := range configMocks {
		encoded, _ := HttpDecoder(mock.Spec.HttpReq.Body)
		k := AdaptiveK(len(reqBuff), 3, 8, 5)
		shingles1 := CreateShingles(encoded, k)
		shingles2 := CreateShingles(reqBuff, k)
		similarity := JaccardSimilarity(shingles1, shingles2)

		log.Debugf("Jaccard Similarity:%f\n", similarity)

		if mxSim < similarity {
			mxSim = similarity
			mxIdx = idx
		}
	}
	return mxIdx
}

func IsAsciiPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func HttpEncoder(buffer []byte) string {
	//Encode the buffer to string
	encoded := string(buffer)
	return encoded
}
func Fuzzymatch(tcsMocks []*models.Mock, reqBuff []byte, h *hooks.Hook) (bool, *models.Mock) {
	com := HttpEncoder(reqBuff)
	for _, mock := range tcsMocks {
		encoded, _ := HttpDecoder(mock.Spec.HttpReq.Body)
		if string(encoded) == string(reqBuff) || mock.Spec.HttpReq.Body == com {

			log.Debug(Emoji, "matched in first loop")

			return true, mock
		}
	}
	// convert all the configmocks to string array
	mockString := make([]string, len(tcsMocks))
	for i := 0; i < len(tcsMocks); i++ {
		mockString[i] = string(tcsMocks[i].Spec.HttpReq.Body)
	}
	// find the closest match
	if IsAsciiPrintable(string(reqBuff)) {
		idx := findStringMatch(string(reqBuff), mockString)
		if idx != -1 {

			log.Debug(Emoji, "Returning mock from String Match")

			return true, tcsMocks[idx]
		}
	}
	idx := findBinaryMatch(tcsMocks, reqBuff, h)
	if idx != -1 {
		return true, tcsMocks[idx]
	}
	return false, &models.Mock{}
}

func isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0] == 0x16 && data[1] == 0x03 && (data[2] == 0x00 || data[2] == 0x01 || data[2] == 0x02 || data[2] == 0x03)
}

func HandleTLSConnection(conn net.Conn) (net.Conn, error) {
	//Load the CA certificate and private key

	var err error
	caPrivKey, err = helpers.ParsePrivateKeyPEM(CaPKey)
	if err != nil {
		return nil, err
	}
	caCertParsed, err = helpers.ParseCertificatePEM(CaCrt)
	if err != nil {
		return nil, err
	}

	// Create a TLS configuration
	config := &tls.Config{
		GetCertificate: certForClient,
	}

	// Wrap the TCP connection with TLS
	tlsConn := tls.Server(conn, config)
	// Perform the handshake
	err = tlsConn.Handshake()

	if err != nil {
		return nil, err
	}
	// Use the tlsConn for further communication
	// For example, you can read and write data using tlsConn.Read() and tlsConn.Write()

	// Here, we simply close the connection
	return tlsConn, nil
}

func certForClient(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Generate a new server certificate and private key for the given hostname
	destinationUrl = clientHello.ServerName

	cfsslLog.Level = cfsslLog.LevelError

	serverReq := &csr.CertificateRequest{
		//Make the name accordng to the ip of the request
		CN: clientHello.ServerName,
		Hosts: []string{
			clientHello.ServerName,
		},
		KeyRequest: csr.NewKeyRequest(),
	}

	serverCsr, serverKey, err := csr.ParseRequest(serverReq)
	if err != nil {
		return nil, fmt.Errorf(Emoji+"failed to create server CSR: %v", err)
	}
	cryptoSigner, ok := caPrivKey.(crypto.Signer)
	if !ok {
		fmt.Errorf(Emoji + "failed to sign crypto key")
	}
	signerd, err := local.NewSigner(cryptoSigner, caCertParsed, signer.DefaultSigAlgo(cryptoSigner), nil)
	if err != nil {
		return nil, fmt.Errorf(Emoji+"failed to create signer: %v", err)
	}

	serverCert, err := signerd.Sign(signer.SignRequest{
		Hosts:   serverReq.Hosts,
		Request: string(serverCsr),
		Profile: "web",
	})
	if err != nil {
		return nil, fmt.Errorf(Emoji+"failed to sign server certificate: %v", err)
	}

	// Load the server certificate and private key
	serverTlsCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf(Emoji+"failed to load server certificate and key: %v", err)
	}

	return &serverTlsCert, nil
}
