---
description: A short summary of how the KDC chooses the encryption type for tickets and session keys in the AS and TGS exchanges on current domain controllers.
---

# Encryption Type Negotiation

How the KDC decides which encryption algorithm to use for each part of the AS and TGS
exchanges.  This page is the short version for a domain controller that has the April 2026
update or later.  The full input list, the precedence ladder, and worked examples are in the
[Etype Decision Guide](etype-decision-guide.md).

---

## Core Principle

Every Kerberos message that contains encrypted data carries an **etype** identifier that tells
the recipient which algorithm was used.  There is no single "etype for this ticket."  A
reply contains **several independently selected etypes**:

- the **ticket** is encrypted with a key of the *target* principal (krbtgt for a TGT, the
  service account for a service ticket), so its etype is decided by that principal's
  configuration and keys;
- the **session key** inside it has to be usable by the *client*, so its etype must be one
  the client offered;
- the **encrypted part of the reply** uses a key the client already holds.

The client's etype list therefore influences the session key, not the ticket.  The one
exception is the `KdcUseRequestedEtypesForTickets` registry value, which should never be
set (see [Registry Settings](registry.md#kdcuserequestedetypesfortickets)).

---

## AS Exchange (TGT Request)

### Step 1: Client Sends AS-REQ

The client sends a list of supported etypes in the `etype` field of the AS-REQ body, ordered
by preference.  A typical capture from a current Windows client shows:

```
AES256-CTS-HMAC-SHA1-96 (18)
AES128-CTS-HMAC-SHA1-96 (17)
RC4-HMAC (23)
RC4-HMAC-EXP (24)
RC4-HMAC-OLD-EXP (-135)
```

The exact list varies by Windows version and policy (the `-135` value is Windows-specific,
per [MS-KILE]; DES appears only where it is still enabled).  The list is controlled by the
client-side **Network security: Configure encryption types allowed for Kerberos** Group
Policy, which writes the `SupportedEncryptionTypes` registry value.

### Step 2: KDC Responds with PA-ETYPE-INFO2

If pre-authentication is required (the default in AD), the KDC replies with
`KDC_ERR_PREAUTH_REQUIRED` and includes **PA-ETYPE-INFO2** data.  This tells the client
which etypes the KDC will accept for pre-authentication and provides the **salt** needed
for AES key derivation.

The KDC builds this list from the **user account's stored keys**.  If the account has AES256,
AES128, and RC4 keys, all three can appear.  If the account has only an RC4 key, only RC4
appears.

### Step 3: Pre-Authentication (PA-ENC-TIMESTAMP)

The client picks the **strongest etype from PA-ETYPE-INFO2 that it also supports** and
encrypts a timestamp with the corresponding key.

### Step 4: KDC Builds the AS-REP

| Component | How the etype is chosen |
|---|---|
| **TGT ticket encryption** | The krbtgt account's keys, subject to the KDC filter.  AES256 on any domain whose krbtgt has AES keys (lab). |
| **TGT session key** | The strongest etype in the client's list that the KDC allows. |
| **AS-REP encrypted part** | The same key the client used for pre-authentication, so the client can decrypt the reply. |

!!! info "The 2026 RC4 change is about service tickets"
    The April 2026 update changed what the KDC assumes for **unset service accounts in the
    TGS exchange**.  It did not change the AS exchange: on every lab build, including the
    enforcing one, a client that asked for RC4 in the AS exchange was still answered with
    RC4.  (The lab notes do not record whether that was the session key or the ticket
    encryption.)  Separately, Microsoft's *What's new in Windows Server 2025* says the KDC
    there "will no longer issue Ticket Granting Tickets using RC4 encryption".  The one
    Server 2025 build in the lab (26100.32522, the March 2026 update) was among the builds
    that answered an RC4 request with RC4, so with the session-key-or-ticket question
    unrecorded, this site has neither confirmed nor refuted that statement.

---

## TGS Exchange (Service Ticket Request)

### Step 1: Client Sends TGS-REQ

The TGS-REQ contains the **TGT**, an **Authenticator** encrypted with the TGT session key,
and the client's **etype list**.

### Step 2: KDC Builds the TGS-REP

| Component | How the etype is chosen |
|---|---|
| **Service ticket encryption** | The strongest etype in the **target account's effective set** for which the account has a key, provided the KDC filter allows it.  The effective set is the account's `msDS-SupportedEncryptionTypes` if nonzero, otherwise the DC's `DefaultDomainSupportedEncTypes`, otherwise the built-in default.  The client's preference is **not** consulted. |
| **Service ticket session key** | An etype from the client's list that the account's effective set and the KDC filter also allow.  Where more than one qualifies, the lab results follow the **client's order of preference**, not strength.  With nothing in common the request fails with `KDC_ERR_ETYPE_NOSUPP`. |
| **TGS-REP encrypted part** | The TGT session key's etype. |

--8<-- "includes/ddset-default-by-build.md"

!!! warning "Service ticket etype depends on the target account, not the client"
    A client can offer nothing but AES and still be handed an RC4 **ticket** if the target
    account's effective set is RC4-only (an explicit `msDS-SupportedEncryptionTypes = 4`, an
    explicit DDSET that contains RC4 but no AES, or an unset account on a DC without the
    April 2026 update).  Conversely, an RC4-first request against an AES-capable account
    still gets an AES256 ticket.

### Session keys and RC4-only clients

How the session key is chosen for a client that offers only RC4 changed with the April 2026
update (lab, Server 2022):

| Target account | Before the April 2026 update | April 2026 update or later (20348.5020) |
|---|---|---|
| Unset | RC4 ticket, RC4 session key | **Refused** (Kdcsvc 203) |
| `0x18` (AES-only) | AES256 ticket, RC4 session key | **Refused** (Kdcsvc 208) |
| `0x1C` (RC4 + AES) | AES256 ticket, RC4 session key | AES256 ticket, RC4 session key |
| `0x04` (RC4) | RC4 ticket, RC4 session key | RC4 ticket, RC4 session key |

The reverse mismatch fails on every build: a client that offers only AES256 against an
RC4-only account, or only AES256 against an AES128-only account, gets
`KDC_ERR_ETYPE_NOSUPP`.

A client that offers both but lists RC4 **first** is a third case.  Against a `0x1C` account
on 20348.5020, a client whose list ran RC4 first and AES256 last received the AES256 ticket
with an **RC4** session key (lab, June 2026; impacket's default etype list up to release
0.13.1).  A Windows client, which
lists AES256 first, received an AES256 session key for a `0x1C` account on the pre-April
build.  The session key followed the client's order, not the strongest common etype.

### Split etypes and the AES-SK bit

Ticket and session-key etypes are chosen separately, so they can differ ([RFC 4120]
section 3.1.3 takes the session key type from the client's etype list).  The
November 2022 update (CVE-2022-37966, KB5021131) made one particular split the default: it
introduced the `AES256-CTS-HMAC-SHA1-96-SK` bit (`0x20`) and a built-in default of `0x27`,
so that an unset account kept its RC4 **ticket** but an AES-capable client received an
**AES256 session key**:

```
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

You will still see this output for an unset account on a DC that does not yet have the
April 2026 update (lab, Windows `klist`).  For an account explicitly set to `0x24`,
Microsoft's KB5073381 describes the value as "RC4 with AES session keys", and the lab saw
this output on the pre-April build.  On the enforcing build the only test used a client that
lists RC4 first, which received an RC4 session key; a Windows-client retest has not been
done.  On a patched DC an unset account gets AES256 for both.  See
[the AES-SK split](etype-decision-guide.md#the-aes-sk-split-when-ticket-and-session-key-differ).

---

## Decision Reference Table

| What | AS Exchange | TGS Exchange |
|---|---|---|
| **Ticket encryption** | krbtgt's keys + KDC filter (AES256 where krbtgt has AES keys) | Target account's effective etype set + its keys + KDC filter |
| **Session key** | Client etype list + KDC filter (strongest common) | Client etype list ∩ target's effective set ∩ KDC filter, in the client's order of preference (lab); none in common = `KDC_ERR_ETYPE_NOSUPP` |
| **Reply encrypted part** | Same etype as pre-auth (client's key) | Same etype as TGT session key |

!!! tip "Reading klist output"
    When you run `klist` on a Windows client, the `KerbTicket Encryption Type` field shows
    the **ticket encryption** etype and the `Session Key Type` field shows the **session key**
    etype.  For TGTs (server = `krbtgt/DOMAIN`), the ticket etype should be AES256.
    For service tickets, the ticket etype depends on the target account's configuration.

---

## Practical Example

A domain controller with the April 2026 update or later, no
`DefaultDomainSupportedEncTypes` value, a Windows 11 client, and a service account
`svc_sql` with `msDS-SupportedEncryptionTypes` not set:

| Component | Etype | Reason |
|---|---|---|
| TGT ticket | AES256 (18) | krbtgt has AES256 keys; the KDC picks the strongest |
| TGT session key | AES256 (18) | Strongest etype the client offered |
| Service ticket | AES256 (18) | Unset account is treated as `0x18`; `svc_sql` has an AES256 key |
| Service session key | AES256 (18) | Client offered it; `0x18` allows it |

The same request against a DC that does **not** have the April 2026 update returns an RC4
service ticket with an AES256 session key, because the built-in default there is `0x27`.
During a rolling update the result depends on which DC answers.  Setting
`msDS-SupportedEncryptionTypes = 0x18` on `svc_sql` makes the outcome the same on every DC,
which is why explicit values are still worth setting.

If `svc_sql` has **no AES keys** (its password predates AES support, or was set from a hash),
the patched DC cannot satisfy `0x18` and the request fails with `KDC_ERR_ETYPE_NOSUPP`.  Reset
the password; see [Auditing Kerberos Keys](account-key-audit.md).

---

## Further Reading

- [Etype Decision Guide](etype-decision-guide.md) - every input, the precedence ladder,
  common mistakes, and worked examples with Event 4769 output.
- [Registry Settings](registry.md) and [Registry Audit Results](registry-audit.md) - the
  values above and the lab measurements behind them.
- [RC4 Deprecation](rc4-deprecation.md) - the 2026 timeline and the Kdcsvc events.
