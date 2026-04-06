---
---

# Pass-the-Key / Overpass-the-Hash

Using stolen encryption keys to request Kerberos tickets without knowing the password.

This attack converts a stolen credential artifact -- an NT hash or AES key -- into a fully
functional Kerberos TGT. The attacker never needs the plaintext password. Because the resulting
TGT is issued by a real KDC and contains a legitimate PAC, it is indistinguishable from a ticket
obtained through normal logon.

---

## How It Works

The core insight is that Kerberos [pre-authentication](../../protocol/preauth.md) does not require
the plaintext password. It requires the **encryption key** derived from the password. If the
attacker already has the key, they skip the derivation step and go straight to building the
`PA-ENC-TIMESTAMP` structure.

### RC4: The NT Hash IS the Key

When the encryption type is RC4-HMAC (etype 23), the Kerberos key is computed as:

```
RC4 key = MD4(UTF-16LE(password)) = NT hash
```

This is the same NT hash used for NTLM authentication. The two protocols share a key. An attacker
who obtains the NT hash through any means -- LSASS memory dump, DCSync, Kerberoasting, NTDS.dit
extraction -- can use it directly as the RC4 Kerberos key to request a TGT. This is why the
technique is called "overpass-the-hash": it converts an NTLM hash into Kerberos access.

### AES: Different Keys, Same Problem

With AES encryption types (etype 17 and 18), the key derivation uses PBKDF2 with a salt
(`REALM` + principal name), so the AES key is not the same as the NT hash. However, AES keys are
still extractable from:

- LSASS memory (via mimikatz `sekurlsa::ekeys`)
- Keytab files on Linux/Unix systems
- NTDS.dit with offline extraction tools
- DCSync with `lsadump::dcsync`

Once obtained, AES keys work identically -- the attacker encrypts the `PA-ENC-TIMESTAMP` with the
stolen AES key and the KDC issues a TGT.

### Why It Works

The [AS Exchange](../../protocol/as-exchange.md) validates pre-authentication by decrypting the
timestamp with the user's stored key. If decryption succeeds and the timestamp is within the
5-minute skew window, the KDC issues a TGT. The KDC has no way to distinguish between a key
derived from a password typed by the user and a key injected by an attacker -- they are
cryptographically identical.

```
Attacker                                 KDC
   |                                      |
   |  AS-REQ: cname=admin                 |
   |  PA-ENC-TIMESTAMP encrypted          |
   |  with stolen NT hash (RC4 key)       |
   |------------------------------------->|
   |                                      |  Decrypt timestamp with admin's
   |                                      |  stored key -- success
   |  AS-REP: TGT + session key           |
   |<-------------------------------------|
   |                                      |
   |  TGT is now usable for any           |
   |  TGS-REQ, just like a normal logon   |
```

---

## Defend

Preventing pass-the-key requires protecting the key material from extraction in the first place.
The attack itself is a legitimate use of the Kerberos protocol -- the defense is to deny attackers
access to keys.

### Credential Guard

Windows Credential Guard isolates LSASS secrets in a virtualization-based security (VBS)
container. Even a local administrator cannot dump keys from LSASS memory when Credential Guard
is enabled.

!!! warning "Credential Guard limitations"
    Credential Guard protects against LSASS memory dumps but does not prevent DCSync, NTDS.dit
    extraction, or keytab file theft. It is one layer, not a complete solution.

### Protected Users Group

Members of the **Protected Users** security group receive several hardening measures relevant to
this attack:

- NTLM authentication is disabled (no NT hash cached for NTLM)
- Credential delegation and caching are restricted
- TGT lifetime is reduced to 4 hours
- Only AES encryption is used for Kerberos pre-authentication (DES and RC4 disabled)

!!! info "Protected Users does not prevent AES pass-the-key"
    Forcing AES-only authentication raises the bar (the attacker needs AES keys instead of the
    NT hash), but AES keys are still extractable. The primary value is breaking the
    NTLM-hash-to-Kerberos-key equivalence.

### Least-Privilege Administration

Minimize where privileged credentials are exposed:

- Do not log into workstations with Domain Admin accounts
- Use separate admin workstations (PAWs) for Tier 0 administration
- Avoid running services under highly privileged accounts
- Implement tiered administration to contain credential exposure

### Enforce AES-Only Authentication

Disabling RC4 at the domain level (see [RC4 Deprecation](../../security/rc4-deprecation.md))
eliminates the NT-hash-as-Kerberos-key equivalence. Attackers would need the AES key specifically,
which is not interchangeable with NTLM hashes. This does not prevent the attack entirely but
reduces the attack surface.

---

## Detect

Detection focuses on correlating credential theft indicators with subsequent TGT requests.

### Event ID 4768 -- TGT Request Anomalies

Every TGT request generates a 4768 event on the domain controller. Look for:

- TGT requests for privileged accounts from workstations those accounts do not normally use
- TGT requests with RC4 encryption (`0x17`) when the environment is configured for AES
- Bursts of TGT requests from a single source for multiple accounts

```text
Log Name:      Security
Event ID:      4768
Task Category: Kerberos Authentication Service
Keywords:      Audit Success
Account Name:  admin
Ticket Encryption Type: 0x17     <-- RC4, suspicious if AES is expected
Client Address: 10.0.0.50        <-- is this a normal source for this user?
```

### Correlate with LSASS Access (Sysmon Event 10)

The strongest detection signal is correlating credential dump activity with subsequent Kerberos
authentication:

1. Sysmon Event 10: process access to `lsass.exe` with `PROCESS_VM_READ` from an unusual process
2. Followed by Event 4768: TGT request from the same host for a privileged account

This correlation requires a SIEM that can link events across data sources.

### Network Anomalies

- A user authenticating from a machine they have never used before
- TGT requests at unusual times (outside business hours for that user)
- TGT requests from non-domain-joined systems (if you can identify them by IP range)

!!! tip "Honeypot accounts"
    Create a privileged-looking account (e.g., `svc_backup_admin`) with a known NT hash that is
    never used legitimately. Any TGT request for this account is an immediate indicator of
    compromise.

---

## Exploit

### Step-by-Step

1. **Obtain the key** -- extract the NT hash or AES key from one of these sources:
    - LSASS memory: `mimikatz sekurlsa::logonpasswords` or `sekurlsa::ekeys`
    - DCSync: `mimikatz lsadump::dcsync /user:admin`
    - NTDS.dit extraction: offline parsing with `secretsdump.py`
    - Kerberoasting: crack a service ticket to recover the password, then derive the key

2. **Build the AS-REQ** -- construct a `PA-ENC-TIMESTAMP` pre-authentication data block,
   encrypting the current timestamp with the stolen key.

3. **Send to the KDC** -- the KDC decrypts the timestamp, validates it, and returns an AS-REP
   containing a TGT and session key.

4. **Use the TGT** -- the TGT is now cached (in a ccache file on Linux or in LSASS on Windows)
   and can be used for any [TGS Exchange](../../protocol/tgs-exchange.md) -- requesting service
   tickets to access file shares, databases, remote management interfaces, or any other
   Kerberos-authenticated service.

### Protocol View

The AS-REQ sent by the attacker is structurally identical to a legitimate one. The only difference
is that the key was not derived from a password typed by the user -- it was injected from a
stolen credential. The KDC cannot tell the difference.

---

## Tools

### kerbwolf -- kw-tgt

`kw-tgt` performs the complete AS Exchange using a password, NT hash, or AES key. It outputs a
ccache file that can be used with other kerbwolf tools or any tool that reads `KRB5CCNAME`.

```bash
# Overpass-the-hash with NT hash (RC4)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -H :7facdc498ed1680c4fd1448319a8c04f
```

```bash
# Pass-the-key with AES-256
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin --aes256-key aad3b435b51404eeaad3b435b51404ee...
```

```bash
# Standard password authentication (for comparison)
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -p 'Password1!'
```

```bash title="Get TGT via pass-the-hash, then Kerberoast with the resulting ccache"
# Chain: get TGT, then use it for Kerberoasting
kw-tgt -d CORP.LOCAL --dc-ip 10.0.0.1 -u admin -H :7facdc498ed1680c4fd1448319a8c04f
kw-roast -k -c admin.ccache --ldap
```

### Other Tools

| Tool | Command | Notes |
|---|---|---|
| mimikatz | `sekurlsa::pth /user:admin /domain:CORP.LOCAL /ntlm:<hash>` | Injects credentials into a new process on Windows |
| Rubeus | `Rubeus.exe asktgt /user:admin /rc4:<hash> /domain:CORP.LOCAL` | Requests TGT and can inject into current session with `/ptt` |
| impacket | `getTGT.py CORP.LOCAL/admin -hashes :7facdc498ed1680c4fd1448319a8c04f` | Outputs ccache file for use with other impacket tools |
