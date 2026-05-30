# ssh

Transparent SSH tunnel transport layer for gRPC. The server wraps inbound SSH connections as `net.Conn` for a standard `grpc.Server`; the client provides a `grpc.DialOption` that opens gRPC channels over SSH.

Supports Ed25519 host-key auto-generation and SSH agent forwarding for client authentication.

For inter-VM gRPC where SSH's per-user auth model is a poor fit, see the sibling [`wireguard`](https://github.com/grpc-transports/wireguard).

## Module

```
github.com/grpc-transports/ssh
```

## API

### Server

```go
type ServerConfig struct {
    HostKeyPath        string      // path to Ed25519 host key (auto-generated if missing)
    AuthorizedKeysPath string      // path to authorized_keys file
    Logger             *log.Logger
}

// ListenSSH starts an SSH server and returns a net.Listener of gRPC-ready
// connections; pass directly to grpc.Server.Serve.
func ListenSSH(addr string, cfg ServerConfig) (net.Listener, error)
```

### Client

```go
// DialOption returns a grpc.DialOption that tunnels all gRPC traffic over SSH.
// keyPath: path to private key, path to .pub file (selects matching agent key),
//          or "" (all keys offered by the SSH agent).
func DialOption(addr, keyPath, knownHostsPath string) (grpc.DialOption, error)
```

## Usage

**Server side (e.g. `weft agent`):**

```go
lis, err := sshtransport.ListenSSH("unix:"+socketPath, sshtransport.ServerConfig{
    HostKeyPath:        "~/.weft/agent_host_key",
    AuthorizedKeysPath: "~/.weft/authorized_keys",
    Logger:             logger,
})
grpcServer.Serve(lis)
```

**Client side (e.g. `weft` CLI):**

```go
opt, err := sshtransport.DialOption("unix:"+sshSocket, keyPath, "")
conn, err := grpc.Dial("passthrough:///target", opt)
```

## Used by

- [`openweft/weft`](https://github.com/openweft/weft) — SSH-secured gRPC listener
- [`openweft/weft-client`](https://github.com/openweft/weft-client) — SSH-tunnelled gRPC client
- [`openweft/weft-webui`](https://github.com/openweft/weft-webui) — SSH-tunnelled gRPC client
- [`openweft/terraform-provider-weft`](https://github.com/openweft/terraform-provider-weft) — provider gRPC transport
