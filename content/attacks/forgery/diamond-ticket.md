# Diamond Ticket

Modifying legitimate tickets to bypass detection of forged tickets.

A Diamond Ticket is a modified legitimate TGT. Where a [Golden Ticket](../forgery/golden-ticket.md) is
forged from scratch and has detectable anomalies in its metadata, a Diamond Ticket starts with a
real TGT obtained through a normal [AS Exchange](../../protocol/as-exchange.md) and then surgically
modifies only the [PAC](../../protocol/tickets.md#pac) contents. The result is a ticket with
legitimate timestamps, correct sequence numbers, and proper structure -- but with elevated
privileges injected into the authorization data.

---

## How It Works

The attack requires the same prerequisite as a Golden Ticket -- the `krbtgt` account's secret
key -- but uses it differently.

### Attack Flow

1. **Request a legitimate TGT** -- the attacker authenticates as a low-privilege user through
   the standard [AS Exchange](../../protocol/as-exchange.md) (using a password, NT hash, or AES
   key). The KDC issues a real TGT with legitimate metadata:
    - Valid `authtime` matching the actual authentication time
    - Valid `endtime` matching domain policy (default 10 hours)
    - Correct ticket flags (`FORWARDABLE`, `RENEWABLE`, `INITIAL`, `PRE-AUTHENT`)
    - Proper `PAC_REQUESTOR` SID
    - A real `PA-ENC-TIMESTAMP` was sent, so Event 4768 is logged normally

2. **Decrypt the TGT** -- using the `krbtgt` key, the attacker decrypts the `enc-part` of the
   TGT, exposing the `EncTicketPart` structure including the PAC.

3. **Modify the PAC** -- the attacker changes the `KERB_VALIDATION_INFO` structure inside the
   PAC:
    - Adds high-privilege group SIDs (Domain Admins = 512, Enterprise Admins = 519)
    - Can change the user SID to impersonate a different user
    - Can add Extra SIDs for cross-domain privilege escalation

4. **Re-sign the PAC** -- the attacker recomputes both PAC signatures:
    - `PAC_SERVER_CHECKSUM` -- signed with the `krbtgt` key (since the TGT's "service" is
      `krbtgt`)
    - `PAC_PRIVSVR_CHECKSUM` -- also signed with the `krbtgt` key
    - Both signatures are valid because the attacker has the `krbtgt` key

5. **Re-encrypt the TGT** -- the modified `EncTicketPart` (with the new PAC) is encrypted with
   the `krbtgt` key, producing a valid TGT ciphertext.

6. **Use the modified TGT** -- the attacker presents the modified TGT to the KDC in a TGS-REQ.
   The KDC decrypts it, validates the PAC signatures, and issues service tickets with the
   attacker's elevated group memberships.

### Why It Evades Detection

The key difference from a Golden Ticket:

| Property | Golden Ticket | Diamond Ticket |
|---|---|---|
| `authtime` | Chosen by attacker (often unrealistic) | Matches real authentication time |
| `endtime` | Chosen by attacker (often 10 years) | Matches domain policy (10 hours) |
| Ticket flags | May have unusual combinations | Matches standard AS-REP flags |
| Event 4768 | Missing (no AS Exchange occurred) | Present (real AS Exchange happened) |
| Ticket structure | May have missing or incorrect fields | All fields are legitimate |
| Only change | Everything is fabricated | Only the PAC group memberships |

Because the ticket originated from a real AS Exchange, all the metadata that Golden Ticket
detections rely on -- anomalous lifetimes, missing 4768 events, unusual flag combinations -- is
legitimate.

!!! danger "Same prerequisites, harder to detect"
    A Diamond Ticket requires the `krbtgt` key, which means the domain is already fully
    compromised. The purpose of the Diamond Ticket is not initial access -- it is **stealth
    persistence** that evades the detection mechanisms built to catch Golden Tickets.

---

## Defend

Defenses against Diamond Tickets overlap almost entirely with [Golden Ticket](../forgery/golden-ticket.md)
defenses, since both require the `krbtgt` key.

### KRBTGT Password Rotation

Same as Golden Ticket -- rotate the `krbtgt` password twice, with a full replication cycle
between changes. A Diamond Ticket depends on the `krbtgt` key to decrypt, modify, and re-encrypt
the TGT. Once the key is rotated, the attacker's ability to create new Diamond Tickets is gone.

### Restrict DCSync Privileges

Prevent unauthorized accounts from replicating the `krbtgt` hash. Audit
`Replicating Directory Changes All` permissions regularly.

### Tiered Administration

Prevent `krbtgt` key compromise in the first place by ensuring Tier 0 credentials are never
exposed on lower-tier systems.

### PAC Content Validation

The most effective defense specific to Diamond Tickets is **cross-referencing PAC claims with
Active Directory at service access time**:

- When a service receives a ticket, compare the group SIDs in the PAC against the user's actual
  group memberships in AD
- If the PAC claims Domain Admins but the user is not actually in Domain Admins, flag the access

This requires custom tooling or advanced security products. Microsoft Defender for Identity
performs this type of PAC analysis.

---

## Detect

Diamond Ticket detection is significantly harder than Golden Ticket detection. The ticket
structure is legitimate, the Event 4768 exists, and the timestamps are correct.

### PAC Group Membership Verification

The primary detection method is comparing what the PAC claims against what Active Directory
actually says:

1. Extract the group SIDs from service tickets (requires packet capture or service-level
   instrumentation)
2. Query Active Directory for the user's actual group memberships
3. Alert on discrepancies

!!! warning "This is non-trivial"
    Real-time PAC content inspection is not a standard capability of most SIEMs. This detection
    typically requires Microsoft Defender for Identity, CrowdStrike Falcon Identity Protection, or
    custom tooling that intercepts and decodes Kerberos tickets.

### Behavioral Analytics

Since the ticket metadata is clean, detection shifts to behavioral analysis:

- **Privilege escalation patterns**: a user who has always been a standard domain user suddenly
  accesses Domain Admin-only resources
- **Access anomalies**: sudden access to domain controllers, sensitive file shares, or admin
  tools from a user who has never accessed them
- **Time-based anomalies**: administrative actions occurring during unusual hours

### Advanced Detection Signals

| Signal | Description |
|---|---|
| PAC mismatch | Group SIDs in the PAC do not match the user's actual AD group memberships |
| Account behavior change | Low-privilege account suddenly performing high-privilege actions |
| TGT reuse anomaly | The same TGT session key used across an unusually long period (attacker repeatedly re-modifying) |
| Defender for Identity alerts | Microsoft's tool specifically detects PAC manipulation |

---

## Exploit

### Prerequisites

Same as Golden Ticket:

1. **KRBTGT hash** (NT hash or AES key)
2. **Domain name**
3. **Domain SID**
4. **A valid low-privilege account** to perform the initial AS Exchange

### Step-by-Step

1. **Obtain the KRBTGT key** (same methods as Golden Ticket):

    ```
    mimikatz # lsadump::dcsync /user:krbtgt
    ```

2. **Request a legitimate TGT as a low-privilege user**:

    ```bash
    # Using Rubeus
    Rubeus.exe asktgt /user:jsmith /password:Summer2024! /domain:CORP.LOCAL
    ```

    This generates a real TGT with legitimate metadata and logs Event 4768 on the DC.

3. **Decrypt, modify, and re-encrypt the TGT using the KRBTGT key**:

    ```bash
    # Using Rubeus diamond command
    Rubeus.exe diamond /krbkey:<aes256_key> /user:jsmith /password:Summer2024! /domain:CORP.LOCAL /dc:dc01.corp.local /enctype:aes256 /ticketuser:administrator /ticketuserid:500 /groups:512,519 /ptt
    ```

    Rubeus performs the full flow in one command: requests a TGT, decrypts it with the `krbtgt`
    AES key, modifies the PAC to add Domain Admins (512) and Enterprise Admins (519), re-signs
    and re-encrypts, and injects the result into the current session.

4. **Use the modified TGT**:

    ```
    dir \\dc01.corp.local\c$
    ```

    The KDC accepts the modified TGT because it is encrypted and signed with the correct
    `krbtgt` key. Service tickets are issued with Domain Admin privileges.

---

## Tools

!!! info "kerbwolf does not implement Diamond Tickets"
    Diamond Ticket creation requires the `krbtgt` key and PAC manipulation. kerbwolf focuses on
    the Kerberos authentication exchanges, not ticket modification.

| Tool | Command | Notes |
|---|---|---|
| Rubeus | `Rubeus.exe diamond /krbkey:<key> /user:jsmith /password:pass /enctype:aes256 /ticketuser:administrator /groups:512 /ptt` | Full flow: request, decrypt, modify, re-encrypt, inject |
| impacket | `ticketer.py` with custom PAC modification scripts | Requires manual PAC manipulation; no single built-in command |
