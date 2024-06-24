//go:build windows

package named_pipe

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"lukechampine.com/frand"
	"net"
	"sync"
)

type WinNamedPipeServer struct {
	pipeName      string
	pipeListener  net.Listener
	key           ecdsa.PrivateKey
	activeClients map[string]net.Conn
	mu            sync.Mutex
	logger        *zerolog.Logger
}

type PipeConn struct {
	c net.Conn
	cipher.AEAD
}

type Message struct {
	RequestId string
	Data      []byte
}

func newNamedPipeServer(pipeName string) (namedPipe NamedPipeServer, err error) {
	pipePath := fmt.Sprintf(`\\.\pipe\%s`, pipeName)
	pipeListener, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		return nil, err
	}
	pipe := &WinNamedPipeServer{
		pipeName:      pipeName,
		pipeListener:  pipeListener,
		activeClients: make(map[string]net.Conn),
	}

	return pipe, nil
}

func (s *WinNamedPipeServer) ECDH(client *ecdh.PublicKey) ([]byte, error) {
	ourKey, err := s.key.ECDH()
	if err != nil {
		return nil, err
	}
	return ourKey.ECDH(client)
}

func (s *WinNamedPipeServer) DeriveEncryptionKey(client *ecdh.PublicKey) ([]byte, error) {
	b, err := s.ECDH(client)
	if err != nil {
		return nil, err
	}
	salt := frand.Bytes(32)

	key := argon2.IDKey(b, salt, 1, 64*1024, 4, 32)

	return key, nil

}

func (s *WinNamedPipeServer) AEAD(client *ecdh.PublicKey) (cipher.AEAD, error) {
	k, err := s.DeriveEncryptionKey(client)
	if err != nil {
		return nil, err
	}

	return chacha20poly1305.NewX(k)

}

func (s *WinNamedPipeServer) GetReader(requestId string) (r io.Reader, err error) {
	return s.activeClients[requestId], nil
}

func (s *WinNamedPipeServer) GetWriter(requestId string) (w io.Writer, err error) {
	return s.activeClients[requestId], nil
}

func (s *WinNamedPipeServer) NewClient(requestId string) (err error) {
	// Accept a pipe connection from a client. pipeListener.Accept is a
	// blocking call until a client connects to the named pipe
	// When a new client connects to the named pipe, a new "instance" of
	// the pipe is created
	conn, err := s.pipeListener.Accept()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.activeClients[requestId] = conn
	s.mu.Unlock()
	return nil
}
