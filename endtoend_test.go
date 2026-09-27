package sshtransport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"

	sshtransport "github.com/grpc-transports/ssh"
)

// ⛔ DialOption WAS AT 0%. Every test in transport_test.go exercises a helper —
// splitAddr, isAuthorized, loadAuthorizedKeys, loadOrCreateHostKey — and not
// one of them dials. The client half of this transport, which is the half a
// caller actually holds, had never been run.
//
// The scaffolding below is the one the WebRTC and WebSocket transports beside
// this one use: a raw-bytes codec and a hand-written ServiceDesc, so the test
// depends on gRPC and not on protoc.

const (
	testCodec  = "sshtransport-rawbytes"
	testMethod = "/sshtransport.Echo/Stream"
)

type rawCodec struct{}

func (rawCodec) Name() string                  { return testCodec }
func (rawCodec) Marshal(v any) ([]byte, error) { return *v.(*[]byte), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	b := v.(*[]byte)
	*b = append((*b)[:0], data...)
	return nil
}

func init() { encoding.RegisterCodec(rawCodec{}) }

var echoDesc = grpc.ServiceDesc{
	ServiceName: "sshtransport.Echo",
	HandlerType: (*any)(nil),
	Streams: []grpc.StreamDesc{{
		StreamName:    "Stream",
		Handler:       echoHandler,
		ServerStreams: true,
		ClientStreams: true,
	}},
}

func echoHandler(_ any, stream grpc.ServerStream) error {
	for {
		var msg []byte
		if err := stream.RecvMsg(&msg); err != nil {
			return err
		}
		reply := append([]byte("echo:"), msg...)
		if err := stream.SendMsg(&reply); err != nil {
			return err
		}
	}
}

// clientKey writes a real ed25519 private key in OpenSSH PEM form and the
// matching authorized_keys line, and returns both paths. A key the package's
// own loader reads, not a fixture shaped like one.
func clientKey(t *testing.T) (keyPath, authorizedPath string) {
	t.Helper()
	dir := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authorizedPath = filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorizedPath, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, authorizedPath
}

// serve starts a real SSH server on loopback carrying a real gRPC service.
func serve(t *testing.T, authorizedPath string) string {
	t.Helper()
	lis, err := sshtransport.ListenSSH("tcp:127.0.0.1:0", sshtransport.ServerConfig{
		HostKeyPath:        filepath.Join(t.TempDir(), "host_ed25519"),
		AuthorizedKeysPath: authorizedPath,
		// The package logs a line per connection; a test that prints the
		// server's chatter hides its own failure message.
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	gs.RegisterService(&echoDesc, nil)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		_ = lis.Close()
		gs.Stop()
	})
	return "tcp:" + lis.Addr().String()
}

// TestGRPCOverARealSSHConnection is the claim this package makes: an ordinary
// grpc.Server on a net.Listener, an ordinary client holding a grpc.DialOption,
// and an SSH connection in between that neither of them knows about.
func TestGRPCOverARealSSHConnection(t *testing.T) {
	keyPath, authorizedPath := clientKey(t)
	addr := serve(t, authorizedPath)

	// knownHostsPath is empty on purpose: the server's host key is generated
	// fresh in a temporary directory, so there is nothing a known_hosts file
	// could have been written from. The package documents that as "NOT for
	// production", and TestDialOptionRejectsAnUnknownHost below covers the
	// other side of that.
	opt, err := sshtransport.DialOption(addr, keyPath, "")
	if err != nil {
		t.Fatalf("DialOption: %v", err)
	}
	cc, err := grpc.NewClient("passthrough:///ssh",
		opt,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype(testCodec)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := cc.NewStream(ctx, &echoDesc.Streams[0], testMethod)
	if err != nil {
		t.Fatalf("opening the stream: %v", err)
	}

	// Several messages, both ways, of different sizes: a transport that
	// carries one may still be framing them wrong.
	for _, want := range []string{"bonjour", "", "deux", string(make([]byte, 4096))} {
		msg := []byte(want)
		if err := stream.SendMsg(&msg); err != nil {
			t.Fatalf("sending %d bytes: %v", len(want), err)
		}
		var got []byte
		if err := stream.RecvMsg(&got); err != nil {
			t.Fatalf("receiving the reply to %d bytes: %v", len(want), err)
		}
		if string(got) != "echo:"+want {
			t.Fatalf("got %d bytes back, want the echo of %d", len(got), len(want))
		}
	}
}

// TestAKeyThatIsNotAuthorizedCannotConnect — the other direction. Without it
// the test above passes just as well for a server that authorises everybody,
// which is the failure that matters here.
func TestAKeyThatIsNotAuthorizedCannotConnect(t *testing.T) {
	_, authorizedPath := clientKey(t)
	addr := serve(t, authorizedPath)

	otherKey, _ := clientKey(t) // a different key, in a different directory
	opt, err := sshtransport.DialOption(addr, otherKey, "")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient("passthrough:///ssh",
		opt,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype(testCodec)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := cc.NewStream(ctx, &echoDesc.Streams[0], testMethod)
	if err == nil {
		msg := []byte("should not arrive")
		if err = stream.SendMsg(&msg); err == nil {
			var got []byte
			err = stream.RecvMsg(&got)
		}
	}
	if err == nil {
		t.Fatal("an unauthorised key was served")
	}
}

// TestDialOptionRefusesBeforeTheFirstCall. The option is built eagerly, so a
// bad key path or an unreadable known_hosts is an error the caller gets while
// they are still writing the dial, rather than a connection failure later.
func TestDialOptionRefusesBeforeTheFirstCall(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := clientKey(t)

	if _, err := sshtransport.DialOption("tcp:127.0.0.1:1", filepath.Join(dir, "no-such-key"), ""); err == nil {
		t.Error("a private key that is not there was accepted")
	}
	if _, err := sshtransport.DialOption("tcp:127.0.0.1:1", keyPath, filepath.Join(dir, "no-such-hosts")); err == nil {
		t.Error("a known_hosts that is not there was accepted")
	}
	// And the control: with both readable, the option is built.
	if _, err := sshtransport.DialOption("tcp:127.0.0.1:1", keyPath, ""); err != nil {
		t.Errorf("a usable pair was refused: %v", err)
	}
}

// TestDialOptionRejectsAnUnknownHost. With a known_hosts that does not name
// the server, the handshake must fail — the check the empty path above skips.
func TestDialOptionRejectsAnUnknownHost(t *testing.T) {
	keyPath, authorizedPath := clientKey(t)
	addr := serve(t, authorizedPath)

	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := sshtransport.DialOption(addr, keyPath, empty)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient("passthrough:///ssh",
		opt,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype(testCodec)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = cc.NewStream(ctx, &echoDesc.Streams[0], testMethod)
	if err == nil {
		t.Fatal("a host absent from known_hosts was accepted")
	}
	if s := err.Error(); !strings.Contains(s, "knownhosts") && !strings.Contains(s, "key is unknown") &&
		!strings.Contains(s, "handshake") && !strings.Contains(s, "DeadlineExceeded") {
		t.Logf("refused, with: %v", err)
	}
}
