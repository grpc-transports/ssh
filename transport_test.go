package sshtransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func generateEd25519Signer(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return signer, sshPub
}

// ─── splitAddr ────────────────────────────────────────────────────────────────

func TestSplitAddr_UnixPrefix(t *testing.T) {
	n, addr := splitAddr("unix:/var/run/vzd.sock")
	if n != "unix" {
		t.Errorf("network = %q, want unix", n)
	}
	if addr != "/var/run/vzd.sock" {
		t.Errorf("address = %q, want /var/run/vzd.sock", addr)
	}
}

func TestSplitAddr_TcpPrefix(t *testing.T) {
	n, addr := splitAddr("tcp:127.0.0.1:2222")
	if n != "tcp" {
		t.Errorf("network = %q, want tcp", n)
	}
	if addr != "127.0.0.1:2222" {
		t.Errorf("address = %q, want 127.0.0.1:2222", addr)
	}
}

func TestSplitAddr_NoPrefix(t *testing.T) {
	n, addr := splitAddr("localhost:9000")
	if n != "tcp" {
		t.Errorf("network = %q, want tcp", n)
	}
	if addr != "localhost:9000" {
		t.Errorf("address = %q, want localhost:9000", addr)
	}
}

func TestSplitAddr_TooShort(t *testing.T) {
	n, addr := splitAddr("tcp")
	if n != "tcp" || addr != "tcp" {
		t.Errorf("short: got (%q,%q), want (tcp,tcp)", n, addr)
	}
}

// ─── isAuthorized ─────────────────────────────────────────────────────────────

func TestIsAuthorized_KeyPresent(t *testing.T) {
	_, pub := generateEd25519Signer(t)
	if !isAuthorized(pub, []ssh.PublicKey{pub}) {
		t.Error("expected authorized key to be accepted")
	}
}

func TestIsAuthorized_KeyAbsent(t *testing.T) {
	_, pub1 := generateEd25519Signer(t)
	_, pub2 := generateEd25519Signer(t)
	if isAuthorized(pub2, []ssh.PublicKey{pub1}) {
		t.Error("expected different key to be rejected")
	}
}

func TestIsAuthorized_EmptyList(t *testing.T) {
	_, pub := generateEd25519Signer(t)
	if isAuthorized(pub, nil) {
		t.Error("expected empty list to reject any key")
	}
}

// ─── loadAuthorizedKeys ───────────────────────────────────────────────────────

func TestLoadAuthorizedKeys_EmptyPath(t *testing.T) {
	keys, err := loadAuthorizedKeys("")
	if err != nil || keys != nil {
		t.Errorf("empty path: got (%v, %v), want (nil, nil)", keys, err)
	}
}

func TestLoadAuthorizedKeys_MissingFile(t *testing.T) {
	keys, err := loadAuthorizedKeys("/non/existent/authorized_keys")
	if err != nil || keys != nil {
		t.Errorf("missing file: got (%v, %v), want (nil, nil)", keys, err)
	}
}

func TestLoadAuthorizedKeys_SingleKey(t *testing.T) {
	_, pub := generateEd25519Signer(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("single key: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if ssh.FingerprintSHA256(keys[0]) != ssh.FingerprintSHA256(pub) {
		t.Error("fingerprint mismatch")
	}
}

func TestLoadAuthorizedKeys_MultipleKeys(t *testing.T) {
	_, pub1 := generateEd25519Signer(t)
	_, pub2 := generateEd25519Signer(t)
	content := append(ssh.MarshalAuthorizedKey(pub1), ssh.MarshalAuthorizedKey(pub2)...)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadAuthorizedKeys(path)
	if err != nil || len(keys) != 2 {
		t.Errorf("two keys: got (%d, %v), want (2, nil)", len(keys), err)
	}
}

// ─── loadOrCreateHostKey ──────────────────────────────────────────────────────

func TestLoadOrCreateHostKey_CreatesNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	signer, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("key file not persisted: %v", err)
	}
}

func TestLoadOrCreateHostKey_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	s1, _ := loadOrCreateHostKey(path)
	s2, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if ssh.FingerprintSHA256(s1.PublicKey()) != ssh.FingerprintSHA256(s2.PublicKey()) {
		t.Error("reloaded key fingerprint differs")
	}
}

// ─── hostKeyCallback ──────────────────────────────────────────────────────────

func TestHostKeyCallback_EmptyPath(t *testing.T) {
	cb, err := hostKeyCallback("")
	if err != nil || cb == nil {
		t.Errorf("empty path: err=%v cb=%v", err, cb)
	}
}

func TestHostKeyCallback_ValidFile(t *testing.T) {
	_, pub := generateEd25519Signer(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := hostKeyCallback(path)
	if err != nil || cb == nil {
		t.Errorf("valid path: err=%v cb=%v", err, cb)
	}
}

func TestHostKeyCallback_MissingFile(t *testing.T) {
	if _, err := hostKeyCallback("/non/existent/known_hosts"); err == nil {
		t.Error("expected error for missing known_hosts")
	}
}

// ─── authMethods ──────────────────────────────────────────────────────────────

func TestAuthMethods_PrivateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	methods, err := authMethods(path)
	if err != nil || len(methods) != 1 {
		t.Errorf("private key: err=%v methods=%d", err, len(methods))
	}
}

func TestAuthMethods_MissingFile(t *testing.T) {
	if _, err := authMethods("/non/existent/key"); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestAuthMethods_EmptyPath_NoAgent(t *testing.T) {
	old := os.Getenv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AUTH_SOCK")
	defer os.Setenv("SSH_AUTH_SOCK", old)
	if _, err := authMethods(""); err == nil {
		t.Error("expected error when SSH_AUTH_SOCK unset")
	}
}

// ─── sshAddr ──────────────────────────────────────────────────────────────────

func TestSSHAddr(t *testing.T) {
	a := sshAddr{"example:1234"}
	if a.Network() != "ssh" {
		t.Errorf("Network() = %q, want ssh", a.Network())
	}
	if a.String() != "example:1234" {
		t.Errorf("String() = %q, want example:1234", a.String())
	}
}

// ─── chanListener ─────────────────────────────────────────────────────────────

func TestChanListener_CloseReturnsNil(t *testing.T) {
	ch := make(chan net.Conn)
	cl := &chanListener{ch: ch, addr: sshAddr{"test"}}
	if err := cl.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestChanListener_AcceptOnClosedChannel(t *testing.T) {
	ch := make(chan net.Conn)
	close(ch)
	cl := &chanListener{ch: ch, addr: sshAddr{"test"}}
	if _, err := cl.Accept(); err != net.ErrClosed {
		t.Errorf("Accept on closed = %v, want net.ErrClosed", err)
	}
}

func TestChanListener_Addr(t *testing.T) {
	want := sshAddr{"myaddr"}
	cl := &chanListener{ch: make(chan net.Conn), addr: want}
	if cl.Addr() != want {
		t.Errorf("Addr() = %v, want %v", cl.Addr(), want)
	}
}

// ─── Integration: full client/server roundtrip ────────────────────────────────

func TestIntegration_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host_key")
	authKeysPath := filepath.Join(dir, "authorized_keys")

	clientSigner, clientPub := generateEd25519Signer(t)
	if err := os.WriteFile(authKeysPath, ssh.MarshalAuthorizedKey(clientPub), 0o600); err != nil {
		t.Fatal(err)
	}

	lis, err := ListenSSH("tcp:127.0.0.1:0", ServerConfig{
		HostKeyPath:        hostKeyPath,
		AuthorizedKeysPath: authKeysPath,
	})
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	defer lis.Close()

	serverAddr := lis.Addr().String()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverErrCh <- err
		} else {
			serverConnCh <- conn
		}
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}
	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sconn, chans, reqs, err := ssh.NewClientConn(rawConn, serverAddr, clientCfg)
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	client := ssh.NewClient(sconn, chans, reqs)
	defer client.Close()

	ch, reqs2, err := client.OpenChannel(grpcChannelType, nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	go ssh.DiscardRequests(reqs2)

	var serverConn net.Conn
	select {
	case serverConn = <-serverConnCh:
	case err := <-serverErrCh:
		t.Fatalf("server Accept: %v", err)
	}

	want := []byte("hello grpc")
	go func() { ch.Write(want) }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("server got %q, want %q", got, want)
	}

	reply := []byte("ok from server")
	go func() { serverConn.Write(reply) }()
	gotReply := make([]byte, len(reply))
	if _, err := io.ReadFull(ch, gotReply); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Errorf("client got %q, want %q", gotReply, reply)
	}
}

// TestAuthCallback_BypassesAuthorizedKeys verifies the AuthCallback hook
// authorises a key that is NOT in authorized_keys. The callback wins when
// it returns a nil error and non-nil *ssh.Permissions; the file-based
// check never runs. This is the seam used by OpenPubkey / FIDO2 / sigstore
// integrations.
func TestAuthCallback_BypassesAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host_key")
	// authorized_keys file is intentionally absent — the callback is the
	// only valid auth path.

	clientSigner, clientPub := generateEd25519Signer(t)
	var seenFP string
	cb := func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		seenFP = ssh.FingerprintSHA256(key)
		return &ssh.Permissions{
			Extensions: map[string]string{"auth": "callback"},
		}, nil
	}

	lis, err := ListenSSH("tcp:127.0.0.1:0", ServerConfig{
		HostKeyPath:  hostKeyPath,
		AuthCallback: cb,
	})
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	defer lis.Close()
	go func() { _, _ = lis.Accept() }()

	rawConn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sconn, _, _, err := ssh.NewClientConn(rawConn, lis.Addr().String(), &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	})
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	defer sconn.Close()

	wantFP := ssh.FingerprintSHA256(clientPub)
	if seenFP != wantFP {
		t.Errorf("callback saw fp %q, want %q", seenFP, wantFP)
	}
}

// TestAuthCallback_FallsBackToAuthorizedKeys verifies that an AuthCallback
// returning an error doesn't lock out a key listed in authorized_keys —
// the file-based check still runs. Prevents misconfigured callbacks from
// turning into a self-lockout.
func TestAuthCallback_FallsBackToAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host_key")
	authKeysPath := filepath.Join(dir, "authorized_keys")

	clientSigner, clientPub := generateEd25519Signer(t)
	if err := os.WriteFile(authKeysPath, ssh.MarshalAuthorizedKey(clientPub), 0o600); err != nil {
		t.Fatal(err)
	}

	// Callback always refuses — the file MUST be consulted next.
	cb := func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, io.EOF
	}

	lis, err := ListenSSH("tcp:127.0.0.1:0", ServerConfig{
		HostKeyPath:        hostKeyPath,
		AuthorizedKeysPath: authKeysPath,
		AuthCallback:       cb,
	})
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	defer lis.Close()
	go func() { _, _ = lis.Accept() }()

	rawConn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sconn, _, _, err := ssh.NewClientConn(rawConn, lis.Addr().String(), &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	})
	if err != nil {
		t.Fatalf("ssh handshake (callback should fall back to authorized_keys): %v", err)
	}
	sconn.Close()
}
