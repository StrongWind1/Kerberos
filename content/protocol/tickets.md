# Ticket Structure

What is inside a Kerberos ticket and what each field means.

Kerberos tickets are the core data structure of the protocol. Every authentication decision
ultimately depends on what is inside a ticket. There are two types -- the **Ticket-Granting Ticket
(TGT)** and the **Service Ticket** -- but they share the same internal structure. The difference is
which key encrypts them and which service they are for.

---

## Two Types, One Structure

| | TGT | Service Ticket |
|---|---|---|
| **Issued by** | Authentication Service (AS) | Ticket-Granting Service (TGS) |
| **Encrypted with** | KDC's secret key (`krbtgt` account) | Target service's secret key |
| **Used to access** | The TGS (to request service tickets) | The target service |
| **`sname` value** | `krbtgt/REALM` | Service SPN (e.g., `HTTP/web.corp.local`) |
| **Obtained via** | [AS Exchange](as-exchange.md) | [TGS Exchange](tgs-exchange.md) |

!!! info "Same structure, different keys"
    A TGT is technically just a service ticket for the `krbtgt` service. The KDC treats the TGT
    the same way any service treats its own service ticket -- it decrypts it with its own key and
    trusts the contents.

---

## Ticket Outer Structure

Per [RFC 4120 &sect;5.3], the ticket has this ASN.1 structure:

```
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno    [0] INTEGER (5),
    realm      [1] Realm,
    sname      [2] PrincipalName,
    enc-part   [3] EncryptedData -- EncTicketPart
}
```

| Field | Description |
|---|---|
| `tkt-vno` | Version number. Always `5` for Kerberos V5. |
| `realm` | The realm (domain) that issued the ticket. Also identifies the server's realm. |
| `sname` | Server name -- the principal name of the service. For a TGT this is `krbtgt/CORP.LOCAL`. For a service ticket this is the SPN, such as `HTTP/web.corp.local`. |
| `enc-part` | The encrypted portion containing all the actual ticket data. Only the service (or KDC for TGTs) can decrypt this. |

The `realm` and `sname` fields are in cleartext. Anyone observing network traffic can see which
service a ticket is for. The sensitive data is all inside `enc-part`.

---

## EncTicketPart -- The Encrypted Contents

The encrypted portion of the ticket is where all the important data lives. Per
[RFC 4120 &sect;5.3]:

```
EncTicketPart ::= [APPLICATION 3] SEQUENCE {
    flags              [0]  TicketFlags,
    key                [1]  EncryptionKey,
    crealm             [2]  Realm,
    cname              [3]  PrincipalName,
    transited          [4]  TransitedEncoding,
    authtime           [5]  KerberosTime,
    starttime          [6]  KerberosTime OPTIONAL,
    endtime            [7]  KerberosTime,
    renew-till         [8]  KerberosTime OPTIONAL,
    caddr              [9]  HostAddresses OPTIONAL,
    authorization-data [10] AuthorizationData OPTIONAL
}
```

### Field Descriptions

`flags`
:   Bit field controlling ticket behavior. See the [Ticket Flags](#ticket-flags) table below.

`key`
:   The **session key** for communication between the client and the service. This is a randomly
    generated symmetric key created by the KDC. For a TGT, this is the TGT Session Key. For a
    service ticket, this is the Service Session Key used in the [AP Exchange](ap-exchange.md).

`crealm`
:   The client's realm (domain). For example, `CORP.LOCAL`.

`cname`
:   The client's principal name. For example, `alice`.

`transited`
:   Records which intermediate realms were traversed during [cross-realm
    authentication](cross-realm.md). Used for policy checking -- services can reject tickets that
    passed through untrusted realms.

`authtime`
:   The time of the client's original authentication (when the AS issued the initial TGT). This
    timestamp is copied into all subsequent tickets derived from that TGT.

`starttime`
:   When the ticket becomes valid. If omitted, the ticket is valid from `authtime`. Used for
    postdated tickets.

`endtime`
:   When the ticket expires. Default is 10 hours for TGTs in Active Directory. After this time,
    the ticket is no longer accepted.

`renew-till`
:   The absolute latest time the ticket can be renewed to. Default is 7 days for TGTs in Active
    Directory. Only present if the RENEWABLE flag is set.

`caddr`
:   Optional list of IP addresses from which the ticket is valid. Rarely used in modern AD
    environments because NAT and DHCP make address restrictions impractical.

`authorization-data`
:   Extensible field for authorization information. In Active Directory, this is where the
    **Privilege Attribute Certificate (PAC)** lives. See the [PAC section](#pac) below.

---

## Ticket Flags

Per [RFC 4120 &sect;5.3], each flag is a single bit in the `flags` field. Here is what each flag
means:

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | `reserved` | Reserved for future use. |
| 1 | `FORWARDABLE` | The TGS is allowed to issue a new TGT with a different network address based on this ticket. Enables [delegation](delegation.md) scenarios where a service needs to act on the user's behalf from a different host. |
| 2 | `FORWARDED` | This ticket has been forwarded, or was issued based on a forwarded TGT. A service can check this flag to detect that delegation occurred. |
| 3 | `PROXIABLE` | The TGS is allowed to issue a service ticket (not a TGT) with a different network address. Similar to FORWARDABLE, but applies only to service tickets, not TGTs. |
| 4 | `PROXY` | This ticket is a proxy ticket -- it was issued with a different address than the original. |
| 5 | `MAY-POSTDATE` | The TGS is allowed to issue a postdated ticket based on this TGT. Postdated tickets have a future `starttime`. |
| 6 | `POSTDATED` | This ticket has a `starttime` in the future. It was postdated at issuance. |
| 7 | `INVALID` | This ticket is not yet valid and must be validated by the KDC before use. Postdated tickets start in this state. Application servers must reject tickets with this flag set. |
| 8 | `RENEWABLE` | This ticket can be renewed. The client can present it to the TGS before `renew-till` to get a new ticket with a later `endtime`, without re-entering credentials. |
| 9 | `INITIAL` | This ticket was issued through the [AS Exchange](as-exchange.md) (using the client's password or certificate), not through a TGS request. Allows services to require "fresh" authentication. |
| 10 | `PRE-AUTHENT` | The client was pre-authenticated before the KDC issued the initial TGT. See [Pre-Authentication](preauth.md). This flag is copied into all tickets derived from the TGT. |
| 11 | `HW-AUTHENT` | Hardware-based pre-authentication was used (for example, a smart card). |
| 12 | `TRANSITED-POLICY-CHECKED` | The KDC validated the `transited` field against the realm's trust policy. If this flag is not set, the application server must validate the transited field itself or reject the ticket. |
| 13 | `OK-AS-DELEGATE` | The KDC asserts that the target service is trusted for [delegation](delegation.md). The client can use this flag to decide whether to forward its TGT to the service. Per [RFC 4120 &sect;5.3], the client is free to ignore this flag. |
| 15 | `enc_pa_rep` | KDC supports encrypted PA-REP ([RFC 6806 &sect;5]). Set by default on Server 2012+ KDCs. Not to be confused with the `canonicalize` **request option** (kdc-options bit 15 in KDC-REQ-BODY per [RFC 6806 &sect;3]), which is an entirely separate flag in a different message field. |

### Common Flag Combinations

In practice, you will see these flag combinations most often:

| Hex Value | Flags | Meaning |
|---|---|---|
| `0x50e10000` | FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE-AUTHENT, enc_pa_rep | Standard TGT with pre-auth |
| `0x40a10000` | FORWARDABLE, RENEWABLE, PRE-AUTHENT, enc_pa_rep | Standard service ticket |
| `0x40a50000` | FORWARDABLE, RENEWABLE, PRE-AUTHENT, OK-AS-DELEGATE | Service ticket for a service trusted for delegation |

---

## PAC -- Privilege Attribute Certificate { #pac }

The PAC is a Microsoft extension defined in [MS-PAC] that carries Windows authorization data
inside Kerberos tickets. It lives in the `authorization-data` field of the `EncTicketPart`.

Standard Kerberos (RFC 4120) is an **authentication** protocol -- it proves who you are. It does
not handle **authorization** -- determining what you are allowed to do. Microsoft solved this by
embedding authorization data directly in the ticket through the PAC.

!!! info "Why the PAC matters"
    Windows services use the PAC to build the user's access token. Without the PAC, Windows would
    need to contact a domain controller for every authorization decision. The PAC makes Kerberos
    authentication and Windows authorization work together in a single round trip.

### PAC Contents

The PAC is a collection of buffers, each identified by a type number:

| Buffer Type | Name | Contents |
|---|---|---|
| `0x00000001` | `KERB_VALIDATION_INFO` | User's SID, primary group SID, group membership SIDs, logon time, password last set, account expiration, logon count, bad password count, user account control flags, full name, logon script path, profile path, home directory, and other logon information. This is the main authorization data buffer. |
| `0x0000000A` | `PAC_CLIENT_INFO` | Client name and authentication time. Used by the service to verify the PAC matches the ticket. |
| `0x0000000C` | `UPN_DNS_INFO` | User Principal Name (UPN) and DNS domain name. For example, `alice@corp.local` and `corp.local`. |
| `0x00000006` | `PAC_SERVER_CHECKSUM` | HMAC signature computed using the **service's secret key**. Proves the PAC was not modified after the KDC created it. |
| `0x00000007` | `PAC_PRIVSVR_CHECKSUM` | HMAC signature computed using the **`krbtgt` account's secret key**. Proves the PAC was created by a legitimate KDC, not forged by an attacker who only knows the service key. |
| `0x00000010` | `PAC_TICKET_CHECKSUM` | HMAC signature over the service ticket's `enc-part`, computed using the `krbtgt` key. Introduced with KB5008380 PAC integrity improvements (CVE-2021-42287). Required by [MS-PAC &sect;2.8.3] on Server 2016+. Prevents Silver Tickets from passing PAC validation when `ValidateKdcPacSignature` is enforced. |
| `0x00000011` | `PAC_ATTRIBUTES_INFO` | Flags indicating PAC properties (e.g., whether the PAC was requested by the client). |
| `0x00000012` | `PAC_REQUESTOR_SID` | SID of the account that requested the ticket. Used during PAC re-validation per [MS-KILE &sect;3.3.5.7.1]. |

### PAC Signatures

The PAC carries two cryptographic signatures:

Server Signature (`PAC_SERVER_CHECKSUM`)
:   Computed with the service's secret key. The service validates this signature during the
    [AP Exchange](ap-exchange.md) to confirm the PAC was not tampered with in transit.

KDC Signature (`PAC_PRIVSVR_CHECKSUM`)
:   Computed with the `krbtgt` account's secret key. This signature proves the PAC originated from
    a real KDC. Only the KDC knows the `krbtgt` key, so only the KDC can produce this signature.

!!! warning "PAC validation is not always enforced"
    By default, most Windows services only validate the **server signature**. The KDC signature is
    only checked if PAC validation is explicitly enabled via the registry key
    `ValidateKdcPacSignature` at
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`.

    This means that if an attacker knows the service's secret key, they can forge a PAC with any
    group memberships (a [Silver Ticket](../attacks/forgery/silver-ticket.md) attack) and the service will
    accept it without question. The KDC signature check is the defense against this attack.

!!! note "PAC re-validation on Server 2022+ (KB5008380)"
    On Server 2022 and later DCs with KB5008380+, the KDC re-validates PAC contents during TGS
    exchanges. When a TGT is used in a TGS-REQ, the KDC refreshes group membership from Active
    Directory and updates the PAC in the resulting service ticket. This significantly reduces the
    PAC staleness window compared to pre-2021 DCs, where the PAC was copied unchanged from TGT to
    service ticket.

### KERB_VALIDATION_INFO -- The Authorization Payload

The `KERB_VALIDATION_INFO` structure is the most important part of the PAC. It contains
everything Windows needs to build an access token:

- **User SID** -- e.g., `S-1-5-21-<domain>-1104` (alice's unique security identifier)
- **Primary Group SID** -- e.g., `S-1-5-21-<domain>-513` (Domain Users)
- **Group SIDs** -- list of all security groups the user belongs to
- **Extra SIDs** -- additional SIDs from other domains (used in cross-realm scenarios)
- **User Account Control flags** -- account status (enabled, locked, password expired, etc.)
- **Logon information** -- logon time, logon count, bad password count, password last set

When a Windows service receives a ticket, it reads the `KERB_VALIDATION_INFO` from the PAC and
constructs a Windows access token. This token is then used for all authorization decisions (file
ACLs, share permissions, COM object access, etc.).

---

## Example: Reading Tickets with klist

The `klist` command on Windows displays cached Kerberos tickets. Here is an annotated example:

```
C:\>klist

Current LogonId is 0:0x4c2b5
Cached Tickets: (3)

#0>  Client: alice @ CORP.LOCAL                          ❶
     Server: krbtgt/CORP.LOCAL @ CORP.LOCAL              ❷
     KrbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96 ❸
     Ticket Flags 0x50e10000 -> forwardable proxiable renewable initial pre_authent enc_pa_rep  ❹
     Start Time: 4/3/2026 8:00:00 (local)                ❺
     End Time:   4/3/2026 18:00:00 (local)               ❻
     Renew Time: 4/10/2026 8:00:00 (local)               ❼
     Session Key Type: AES-256-CTS-HMAC-SHA1-96           ❽
     Cache Flags: 0x1 -> PRIMARY
     Kdc Called: dc1.corp.local                           ❾

#1>  Client: alice @ CORP.LOCAL
     Server: HTTP/web.corp.local @ CORP.LOCAL
     KrbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
     Ticket Flags 0x40a10000 -> forwardable renewable pre_authent enc_pa_rep
     Start Time: 4/3/2026 9:15:22 (local)
     End Time:   4/3/2026 18:00:00 (local)
     Renew Time: 4/10/2026 8:00:00 (local)
     Session Key Type: AES-256-CTS-HMAC-SHA1-96
     Cache Flags: 0
     Kdc Called: dc1.corp.local
```

Reading this output:

| Marker | Field | Explanation |
|---|---|---|
| 1 | `Client` | The authenticated principal: `alice` in realm `CORP.LOCAL` |
| 2 | `Server` | Ticket #0 is a TGT (`krbtgt/CORP.LOCAL`). Ticket #1 is a service ticket for `HTTP/web.corp.local`. |
| 3 | `Encryption Type` | The algorithm used to encrypt the ticket itself (AES-256). See [Encryption Types](encryption.md). |
| 4 | `Ticket Flags` | The TGT has `initial` (issued via AS Exchange) and `pre_authent` (pre-auth was used). The service ticket lacks `initial` because it was issued via the TGS. |
| 5 | `Start Time` | When the ticket became valid. |
| 6 | `End Time` | When the ticket expires. Default TGT lifetime is 10 hours. |
| 7 | `Renew Time` | The ticket can be renewed until this time (default: 7 days from initial authentication). |
| 8 | `Session Key Type` | The encryption algorithm for the session key inside the ticket. |
| 9 | `Kdc Called` | Which domain controller issued the ticket. |

!!! tip "klist on Linux"
    On Linux systems using MIT Kerberos or Heimdal, run `klist -e` to show encryption types, or
    `klist -f` to show ticket flags. The output format differs from Windows but contains the same
    information.

---

## Ticket Lifetimes in Active Directory

Active Directory defines default ticket lifetimes through Group Policy
(`Computer Configuration > Windows Settings > Security Settings > Account Policies > Kerberos
Policy`):

| Setting | Default | Description |
|---|---|---|
| Maximum lifetime for user ticket (TGT) | 10 hours | How long a TGT is valid |
| Maximum lifetime for service ticket | 10 hours | How long a service ticket is valid |
| Maximum lifetime for user ticket renewal | 7 days | How long a TGT can be renewed |
| Maximum tolerance for computer clock synchronization | 5 minutes | The acceptable clock skew window |

When a ticket expires, the client must either renew it (if the RENEWABLE flag is set and
`renew-till` has not passed) or request a new one through the [AS Exchange](as-exchange.md) or
[TGS Exchange](tgs-exchange.md).

---

## Summary

- A Kerberos ticket is an encrypted container holding the client's identity, a session key, and
  authorization data
- TGTs and service tickets are the same structure, encrypted with different keys
- The `EncTicketPart` contains everything: flags, session key, client identity, timestamps,
  and the PAC
- Ticket flags control behavior like forwarding, renewal, and delegation eligibility
- The PAC is a Microsoft extension that carries Windows authorization data (SIDs, group
  memberships) inside the ticket
- Two PAC signatures protect integrity: the server signature (validated by default) and the KDC
  signature (validated only if explicitly enabled)
