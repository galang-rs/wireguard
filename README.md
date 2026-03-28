<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT" />
  <img src="https://img.shields.io/badge/Platform-Cross%20Platform-blueviolet?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status" />
</p>

<h1 align="center">🔐 WireGuard Go</h1>

<p align="center">
  <strong>A pure-Go WireGuard VPN client implementation with userspace TUN device.</strong><br/>
  No CGo. No system drivers. No root required for the tunnel itself.
</p>

<p align="center">
  <em>Built from scratch following the official <a href="https://www.wireguard.com/papers/wireguard.pdf">WireGuard whitepaper</a> — implements the full Noise IKpsk2 handshake, ChaCha20-Poly1305 transport encryption, and raw IP packet I/O through a virtual TUN interface.</em>
</p>

---

## ✨ Features

### 🛡️ Full WireGuard Protocol
- **Noise IKpsk2 Handshake** — Complete implementation of the WireGuard cryptographic handshake
- **Curve25519 DH** — Elliptic-curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305 AEAD** — Authenticated encryption for both handshake and transport
- **BLAKE2s Hashing & HMAC** — For key derivation (KDF1/KDF2/KDF3) and MAC computation
- **TAI64N Timestamps** — Replay protection with monotonic timestamps
- **Preshared Key (PSK)** — Optional additional layer of symmetric-key security
- **MAC1 & MAC2** — Denial-of-service protection via BLAKE2s-128

### 🌐 Userspace TUN Device
- **Pure-Go implementation** — No kernel TUN/TAP drivers needed
- **Raw IP packet I/O** — Read/Write raw IPv4/IPv6 packets through the VPN tunnel
- **`net.Conn`-compatible interface** — Implements `Read()`, `Write()`, `LocalAddr()`, `RemoteAddr()`
- **Tunnel info access** — Retrieve assigned IP, gateway, MTU, DNS via `TunnelInfo()`

### ⚙️ Architecture
- **Layered transport stack** — NetworkIO → Muxer → Handshake/Data workers
- **Concurrent worker model** — All protocol layers run as independent goroutines
- **Channel-based message passing** — Zero shared mutable state between workers
- **Graceful shutdown** — Worker manager with coordinated shutdown sequence
- **Functional options pattern** — Flexible `Config` with `WithConfigFile()`, `WithLogger()`, etc.

### 📝 Configuration
- **Standard `.conf` parser** — Reads WireGuard INI-style configuration files
- **Full config support:**
  - `[Interface]` — `PrivateKey`, `Address`, `DNS`, `MTU`
  - `[Peer]` — `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive`
- **Base64 key encoding/decoding** — Standard 32-byte WireGuard keys
- **Config validation** — Ensures minimum required fields are present

### 🧪 Testing
- **Integration tests** — Real VPN connection tests with TCP handshake over TUN
- **HTTP exit IP verification** — Confirms traffic exits through the VPN
- **Raw TCP packet builders** — Full IPv4 + TCP packet construction with checksums

---

## 📦 Installation

```bash
go get github.com/galang-rs/wireguard
```

---

## 🚀 How to Use

### As a Library

```go
package main

import (
    "context"
    "fmt"
    "net"

    "github.com/galang-rs/wireguard/pkg/config"
    "github.com/galang-rs/wireguard/pkg/tunnel"
)

func main() {
    // 1. Load configuration from .conf file
    cfg := config.NewConfig(config.WithConfigFile("wg0.conf"))

    // 2. Start the VPN tunnel
    ctx := context.Background()
    tun, err := tunnel.Start(ctx, &net.Dialer{}, cfg)
    if err != nil {
        panic(err)
    }
    defer tun.Close()

    // 3. Get tunnel info
    ti := tun.TunnelInfo()
    fmt.Printf("Tunnel IP: %s/%s\n", ti.IP, ti.NetMask)
    fmt.Printf("Gateway:   %s\n", ti.GW)
    fmt.Printf("MTU:       %d\n", ti.MTU)

    // 4. Read/Write raw IP packets
    buf := make([]byte, 4096)
    n, _ := tun.Read(buf)  // Read decrypted IP packet from VPN
    fmt.Printf("Received %d bytes\n", n)

    // tun.Write(ipPacket)  // Send IP packet through VPN
}
```

### As a CLI

```bash
# Build the CLI
go build -o wg ./cmd/wg/

# Run with a config file
./wg wg0.conf

# Or use default (wg0.conf in current directory)
./wg
```

### With Programmatic Configuration

```go
cfg := config.NewConfig(
    config.WithWireGuardOptions(&config.WireGuardOptions{
        PrivateKey: myPrivateKey,      // [32]byte
        Address:    "10.0.0.2/24",
        DNS:        []string{"1.1.1.1", "8.8.8.8"},
        MTU:        1420,
        Peer: config.PeerOptions{
            PublicKey:           peerPubKey,  // [32]byte
            Endpoint:            "vpn.example.com:51820",
            AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
            PersistentKeepalive: 25,
        },
    }),
    config.WithLogger(myCustomLogger),
)
```

### WireGuard Config File Format

```ini
[Interface]
PrivateKey = <base64-encoded-32-byte-key>
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = <base64-encoded-32-byte-key>
PresharedKey = <base64-encoded-32-byte-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Running Tests

```bash
# Run integration test (requires valid .conf with active VPN server)
go test ./pkg/vpn/... -v -run TestWGConnectSurfshark -timeout 120s
```

---

## 🏗️ Project Structure

```
wireguard/
├── cmd/
│   └── wg/
│       └── main.go              # CLI entry point
├── internal/
│   ├── bytesx/                  # Byte utilities
│   ├── crypto/
│   │   ├── noise.go             # Noise IKpsk2 protocol primitives
│   │   ├── keypair.go           # Transport encryption keypair
│   │   └── mac.go               # MAC1/MAC2 computation
│   ├── domain/
│   │   ├── message.go           # WireGuard message types
│   │   └── session.go           # Session state & TunnelInfo
│   ├── optional/                # Generic Optional type
│   ├── session/
│   │   └── manager.go           # Session manager (handshake state machine)
│   ├── transport/
│   │   ├── data/                # Data channel worker
│   │   ├── handshake/           # Handshake worker
│   │   ├── muxer/               # Protocol demuxer
│   │   └── networkio/           # UDP I/O layer
│   ├── tunstack/
│   │   └── tun.go               # Userspace TUN device
│   └── worker/
│       └── manager.go           # Goroutine lifecycle manager
├── pkg/
│   ├── config/
│   │   ├── config.go            # Config + functional options
│   │   ├── options.go           # WireGuardOptions & PeerOptions
│   │   └── parser.go            # .conf file parser
│   ├── tunnel/
│   │   └── tunnel.go            # Public tunnel API
│   └── vpn/
│       └── vpn_test.go          # Integration tests
├── go.mod
└── go.sum
```

---

## 🔧 Dependencies

| Package | Purpose |
|---------|---------|
| `golang.org/x/crypto` | Curve25519, ChaCha20-Poly1305, BLAKE2s |
| `golang.org/x/sys` | System-level support (indirect) |

**Zero external dependencies** beyond the Go extended standard library.

---

## 📄 License

```
MIT License

Copyright (c) 2026 Galang Reisduanto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

ADDITIONAL TERMS:

1. Attribution — If you use this software in a product, an acknowledgment
   in the product documentation or "About" section would be appreciated
   but is not required.

2. Non-Endorsement — The name "galang-rs" or "Galang Reisduanto" may not
   be used to endorse or promote products derived from this software without
   specific prior written permission.

3. Good Faith — This software is shared in good faith for the benefit of
   the open-source community. Commercial use is permitted and encouraged.
```

---

## 📬 Feature Requests & Contact

Have an idea, bug report, or custom feature request? Feel free to reach out!

<p align="center">
  <a href="mailto:galangreisduanto@gmail.com">
    <img src="https://img.shields.io/badge/Email-galangreisduanto%40gmail.com-red?style=for-the-badge&logo=gmail&logoColor=white" alt="Email" />
  </a>
</p>

<p align="center">
  📧 <strong>Email:</strong> <a href="mailto:galangreisduanto@gmail.com">galangreisduanto@gmail.com</a>
</p>

---

## ☕ Support & Donate

If this project helped you, consider buying me a coffee! Your support helps keep the project active and maintained.

<p align="center">
  <a href="https://www.paypal.com/paypalme/SAMdues">
    <img src="https://img.shields.io/badge/Donate-PayPal-blue?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate via PayPal" />
  </a>
</p>

<p align="center">
  📧 <strong>PayPal:</strong> <a href="https://paypal.me/SAMdues">galangreisduanto1@gmail.com</a>
</p>

<p align="center">
  Every donation, no matter how small, is greatly appreciated and motivates continued development. 🙏
</p>

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/galang-rs">Galang Reisduanto</a>
</p>
