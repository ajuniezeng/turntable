# Turntable

A Rust command-line tool for generating [sing-box](https://sing-box.sagernet.org/) configuration files from various subscription sources.

## Features

- **Multi-format Subscription Support**: Parse subscriptions in multiple formats:
  - Sing-box native JSON format
  - Base64-encoded URI lists
  - Plain text URI lists (one URI per line)
- **Protocol Support**: Parse and convert proxy URIs for various protocols:
  - Shadowsocks (ss://)
  - VMess (vmess://)
  - VLess (vless://)
  - Trojan (trojan://)
  - Hysteria2 (hysteria2://, hy2://)
  - TUIC (tuic://)

- **Template-based Generation**: Use a sing-box configuration template and merge subscription outbounds automatically

- **Smart Features**:
  - Country code detection from outbound tags (flag emojis → country selectors)
  - Subscription-based selectors (one selector per subscription)
  - IPv4-only filtering (remove IPv6 outbounds)
  - Detour handling (filter or create detour selector)
  - Subscription caching with configurable TTL
  - Diff view between cached and new subscriptions

- **Version Compatibility**: Target specific sing-box versions (1.10 - 1.13) with automatic feature validation

- **Cloud Upload**: Automatically upload generated configs to WebDAV-compatible storage

## Installation

### From Source

```bash
git clone https://github.com/yourusername/turntable.git
cd turntable
cargo install --path .
```

### Build Requirements

- Rust 2024 Edition (1.85+)
- Cargo

## Usage

### Basic Usage

```bash
# Use default config location (~/.config/turntable/generator.toml)
turntable

# Specify a custom generator config
turntable -g /path/to/generator.toml

# Override output path
turntable -o ./custom-output.json

# Enable verbose logging
turntable -v
```

### Command Line Options

```
Options:
  -g, --generator <FILE>  Generator config file path or URL
                          [default: ~/.config/turntable/generator.toml]
  -o, --output <FILE>     Override config output path
  -v, --verbose           Enable debug logging
  -h, --help              Print help
  -V, --version           Print version
```

## Configuration

### Generator Configuration

Create a `generator.toml` file to configure the generation process:

```toml
# Template file (local path or URL)
template = "./templates/1.13.json"

# Output file path
output = "./out/config.json"

# Target sing-box version (1.10, 1.11, 1.12, or 1.13)
target_version = "1.13"

# IPv4-only mode: remove IPv6 outbounds and set DNS strategy to ipv4_only
ipv4_only = false

# Generate country-based selectors from flag emojis in outbound tags
country_code_outbound_selectors = true

# Filter to specific country codes (empty = all countries)
country_codes = ["US", "JP", "HK", "SG"]

# Remove outbounds with detour tags
no_detour = false

# Create a unified detour selector
detour_selector = false

# Cache subscriptions to avoid repeated fetches
cache_subscription = false
cache_ttl = 60  # minutes

# Show diff between cached and new subscriptions
diff_subscription = false

# WebDAV upload configuration
webdav_upload = false
webdav_url = "https://example.com/dav"
webdav_username = "user"
webdav_password = "secret"
upload_path = "/configs/sing-box.json"

# Subscriptions (at least one required)
[[subscriptions]]
name = "Provider1"
url = "https://example.com/subscription"
# Optional: filter outbounds by index (0-based)
# filter = [0, 1, 2]

[[subscriptions]]
name = "Provider2"
url = "https://example.com/another-subscription"
```

### Template File

The template should be a valid sing-box configuration JSON file. Turntable will:

1. Load your template
2. Fetch and parse all subscriptions
3. Generate subscription and country-code selectors
4. Update existing selectors in the template with new selector tags
5. Append all outbounds to the configuration
6. Validate the config against the target sing-box version
7. Write the final configuration to the output file

Example template structure:

```json
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [...]
  },
  "inbounds": [...],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["auto"]
    },
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": []
    }
  ],
  "route": {...}
}
```

## Development

### Building

```bash
cargo build
cargo build --release
```

### Testing

```bash
cargo test
```

### Code Style

```bash
cargo fmt
cargo clippy
```

## Roadmap

### Planned Features

- [ ] **Clash YAML Support**: Parse Clash subscription format
- [ ] **Support More Protocols**: Parse other protocol URIs
- [ ] **Subscription Filtering**: Advanced filtering by name patterns, protocols, etc.
- [ ] **Configuration Profiles**: Support multiple output profiles from one config
- [ ] **Watch Mode**: Monitor subscription changes and auto-regenerate
- [ ] **Plugin System**: Extensible parser and transformer plugins

### Version Compatibility Goals

Continuously track sing-box releases and update validation rules.

## License

This project is licensed under the MIT License, see the [license file](LICENSE) for details.

## Acknowledgments

- [sing-box](https://sing-box.sagernet.org/) - The universal proxy platform
- [Rust](https://www.rust-lang.org/) - A language empowering everyone to build reliable and efficient software
