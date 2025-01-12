# Another SOCKS5 proxy

> [!WARNING]
> The server is under deep development.
> But it will be very useful to get feedback.

## Minimal config file

```bash
[server]
bind_address = "0.0.0.0"
bind_port = 8888
```

## Build & run

```bash
cargo run --release
./simple-proxy -c <config path>
```

## Roadmap

- Logging
- UDP support
- Authentification(Username/Password)
- IPv6
