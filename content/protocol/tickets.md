---
description: What is inside a Kerberos ticket in Active Directory -- the ASN.1 structure, ticket flags, the PAC and its four signatures, klist output, and ticket lifetimes.
---

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

The table describes the TGT a client obtains for its own realm. A cross-realm (referral) TGT is
the exception: it is issued by the TGS of one realm for the TGS of another, through the TGS
exchange, and is encrypted with the inter-realm key the two realms share instead of the `krbtgt`
key ([RFC 4120 &sect;1.2](https://datatracker.ietf.org/doc/html/rfc4120#section-1.2)). See
[Cross-Realm Authentication](cross-realm.md).

---

## Ticket Outer Structure

Per [RFC 4120 &sect;5.3](https://datatracker.ietf.org/doc/html/rfc4120#section-5.3), the ticket has this ASN.1 structure:

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

The encrypted portion of the ticket is where all the important data lives. Its definition, from [RFC 4120 &sect;5.3](https://datatracker.ietf.org/doc/html/rfc4120#section-5.3), is:

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
    authentication](cross-realm.md). RFC 4120 intends it for policy checking -- a service can
    reject tickets that passed through realms it does not trust. Active Directory does not use
    it that way: per [MS-KILE &sect;3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/de260077-1955-447c-a120-af834afe45c2), "KILE does not check for transited domains on
    servers or a KDC."

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

Per [RFC 4120 &sect;5.3](https://datatracker.ietf.org/doc/html/rfc4120#section-5.3), each flag is a single bit in the `flags` field. Here is what each flag
means:

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | `reserved` | Reserved for future use. |
| 1 | `FORWARDABLE` | The TGS is allowed to issue a new TGT with a different network address based on this ticket. Enables [delegation](delegation.md) scenarios where a service needs to act on the user's behalf from a different host. |
| 2 | `FORWARDED` | This ticket has been forwarded, or was issued based on a forwarded TGT. A service can check this flag to detect that delegation occurred. |
| 3 | `PROXIABLE` | The TGS is allowed to issue a service ticket (not a TGT) with a different network address. Similar to FORWARDABLE, but applies only to service tickets, not TGTs. |
| 4 | `PROXY` | This ticket is a proxy ticket -- it was issued with a different address than the original. |
| 5 | `MAY-POSTDATE` | The TGS is allowed to issue a postdated ticket based on this TGT. Postdated tickets have a future `starttime`. Bits 5 to 7 are RFC 4120 features that Active Directory does not offer: per [MS-KILE &sect;3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/de260077-1955-447c-a120-af834afe45c2), "Postdated tickets are not supported in KILE." |
| 6 | `POSTDATED` | This ticket has a `starttime` in the future. It was postdated at issuance. |
| 7 | `INVALID` | This ticket is not yet valid and must be validated by the KDC before use. Postdated tickets start in this state. Application servers must reject tickets with this flag set. |
| 8 | `RENEWABLE` | This ticket can be renewed. The client can present it to the TGS before `renew-till` to get a new ticket with a later `endtime`, without re-entering credentials. |
| 9 | `INITIAL` | This ticket was issued through the [AS Exchange](as-exchange.md) (using the client's password or certificate), not through a TGS request. Allows services to require "fresh" authentication. |
| 10 | `PRE-AUTHENT` | The client was pre-authenticated before the KDC issued the initial TGT. See [Pre-Authentication](preauth.md). This flag is copied into all tickets derived from the TGT. |
| 11 | `HW-AUTHENT` | Defined by RFC 4120 to indicate that hardware-supported pre-authentication was used. Not issued in Active Directory: per [MS-KILE &sect;3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/de260077-1955-447c-a120-af834afe45c2), "KDCs MUST NOT issue a ticket with this flag set or preserve this flag if it is set by another KDC." |
| 12 | `TRANSITED-POLICY-CHECKED` | Defined by [RFC 4120 &sect;2.7](https://datatracker.ietf.org/doc/html/rfc4120#section-2.7) to mean that the KDC validated the `transited` field against the realm's trust policy; a server that sees the flag unset is expected to validate the field itself or reject the ticket. Active Directory does not use it: per [MS-KILE &sect;3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/de260077-1955-447c-a120-af834afe45c2), "KILE does not check for transited domains on servers or a KDC. Application servers MUST ignore the TRANSITED-POLICY-CHECKED flag." |
| 13 | `OK-AS-DELEGATE` | The KDC asserts that the target service is trusted for [delegation](delegation.md). The client can use this flag to decide whether to forward its TGT to the service. Per [RFC 4120 &sect;2.8](https://datatracker.ietf.org/doc/html/rfc4120#section-2.8), the client is free to ignore this flag. |
| 15 | `enc-pa-rep` | The KDC supports the encrypted PA-REP extension used to detect tampering with the request ([RFC 6806 &sect;11](https://datatracker.ietf.org/doc/html/rfc6806#section-11)). A product note in [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/1163bb03-7035-433e-b5a4-802247262d18) (note 42) says Windows Server 2012 through 2019 KDCs set it "if they have FAST enabled"; in this site's lab a Server 2022 DC (build 20348.3207) set it on every ticket it issued. Windows `klist` prints this bit as `name_canonicalize`. Not to be confused with the `canonicalize` **request option** (kdc-options bit 15 in KDC-REQ-BODY per [RFC 6806 &sect;3](https://datatracker.ietf.org/doc/html/rfc6806#section-3)), which is a separate flag in a different message field. |

### Common Flag Combinations

In practice, you will see these flag combinations most often:

| Hex Value | Flags | Meaning |
|---|---|---|
| `0x40e10000` | FORWARDABLE, RENEWABLE, INITIAL, PRE-AUTHENT, enc-pa-rep | Standard TGT obtained by a Windows client with pre-auth |
| `0x50e10000` | FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE-AUTHENT, enc-pa-rep | TGT requested with the proxiable option. Windows clients do not ask for it ([MS-KILE &sect;3.2.5.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/3affa503-59b5-47b6-92aa-ec4b9cf04982): "The client does not set the PROXY or PROXIABLE option"); some non-Windows tooling does, which makes the value a useful detection signal. |
| `0x40a10000` | FORWARDABLE, RENEWABLE, PRE-AUTHENT, enc-pa-rep | Standard service ticket |
| `0x40a50000` | FORWARDABLE, RENEWABLE, PRE-AUTHENT, OK-AS-DELEGATE, enc-pa-rep | Service ticket for a service trusted for delegation |

---

## PAC -- Privilege Attribute Certificate { #pac }

The PAC is a Microsoft extension defined in [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962) that carries Windows authorization data
inside Kerberos tickets. It lives in the `authorization-data` field of the `EncTicketPart`.

Standard Kerberos (RFC 4120) is an **authentication** protocol -- it proves who you are. It does
not handle **authorization** -- determining what you are allowed to do. Microsoft solved this by
embedding authorization data directly in the ticket through the PAC.

!!! info "Why the PAC matters"
    Windows services use the PAC to build the user's access token. Without the PAC, Windows would
    need to contact a domain controller for every authorization decision. The PAC makes Kerberos
    authentication and Windows authorization work together in a single round trip.

### PAC Contents

The PAC is a collection of buffers, each identified by a type number ([MS-PAC &sect;2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399)):

| Buffer Type | Name | Contents |
|---|---|---|
| `0x00000001` | `KERB_VALIDATION_INFO` | User's SID, primary group SID, group membership SIDs, logon time, password last set, account expiration, logon count, bad password count, user account control flags, full name, logon script path, profile path, home directory, and other logon information. This is the main authorization data buffer. |
| `0x00000002` | `PAC_CREDENTIAL_INFO` | The user's NTLM credentials, encrypted with the AS reply key. Present only when the TGT was obtained with PKINIT; see [Pre-Authentication](preauth.md#pkinit-certificate-based-pre-authentication). |
| `0x00000006` | Server checksum | Signature computed with the **service's** key (for a TGT, the `krbtgt` key). |
| `0x00000007` | KDC (privilege server) checksum | Signature computed with the **`krbtgt`** key over the server checksum. |
| `0x0000000A` | `PAC_CLIENT_INFO` | Client name and authentication time. Used to verify the PAC matches the ticket. |
| `0x0000000B` | `S4U_DELEGATION_INFO` | The list of services a ticket has been delegated through. Present only in tickets obtained with [S4U2Proxy](s4u.md#s4u2proxy-service-for-user-to-proxy). |
| `0x0000000C` | `UPN_DNS_INFO` | User Principal Name (UPN) and DNS domain name. For example, `alice@corp.local` and `corp.local`. |
| `0x0000000D` | `PAC_CLIENT_CLAIMS_INFO` | The user's claims, for Dynamic Access Control. |
| `0x0000000E` | `PAC_DEVICE_INFO` | Group memberships of the client's device, present with compound authentication. |
| `0x0000000F` | `PAC_DEVICE_CLAIMS_INFO` | The device's claims. |
| `0x00000010` | Ticket checksum | Signature computed with the **`krbtgt`** key over the ticket itself, minus the PAC. Service tickets only. |
| `0x00000011` | `PAC_ATTRIBUTES_INFO` | Flags describing the PAC, such as whether the client asked for one. Issued in TGTs. |
| `0x00000012` | `PAC_REQUESTOR_SID` | SID of the account that requested the ticket. Issued in TGTs; when the client is from the KDC's own realm, the KDC checks it against the client name during the TGS exchange ([MS-KILE &sect;3.3.5.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2e5dcf34-4b51-44a0-b45a-277ed616ca39)). |
| `0x00000013` | Extended KDC checksum | Signature computed with the **`krbtgt`** key over the entire PAC. Service tickets only. |
| `0x00000014` | `PAC_REQUESTOR_GUID` | Object GUID of the account that requested the ticket. Optional: per [MS-PAC &sect;2.16](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/28b694b8-affd-4b41-8769-6cfb2d3fde59) the buffer "MAY be present in the PAC". |

### PAC Signatures

A PAC carries up to **four** cryptographic signatures. All four are created by the KDC; they
differ in which key is used and in what is covered. [MS-PAC &sect;2.8](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315) defines the signature
format and the two original signatures, server and KDC; its subsections, linked in the table,
define each of the four:

| Signature | Buffer | Key | Covers | Who can verify it |
|---|---|---|---|---|
| Server signature ([MS-PAC &sect;2.8.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/a194aa34-81bd-46a0-a931-2e05b87d1098)) | `0x06` | Target service's long-term key (the `krbtgt` key for a TGT) | The entire PAC, with the signature fields zeroed | The service, and the KDC |
| KDC signature ([MS-PAC &sect;2.8.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3122bf00-ea87-4c3f-92a0-91c0a99f5eec)) | `0x07` | `krbtgt` key | The server signature only | The KDC |
| Ticket signature ([MS-PAC &sect;2.8.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/76c10ef5-de76-44bf-b208-0d8750fc2edd)) | `0x10` | `krbtgt` key | The ticket's encrypted part with the PAC removed | The KDC |
| Extended KDC signature ([MS-PAC &sect;2.8.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/9cf6f6ad-6b76-44b3-aefa-901aa1ff5a08)) | `0x13` | `krbtgt` key | The entire PAC | The KDC |

The ticket signature and the extended KDC signature are added to tickets that are **not**
encrypted with the `krbtgt` key or a trust key -- that is, to service tickets. A TGT carries only
the server and KDC signatures, both made with the `krbtgt` key.

The two newer signatures close specific gaps. The original KDC signature covers only the server
signature, so it says nothing about the rest of the ticket; and anyone who holds the service's key
can recompute the server signature. The ticket signature lets a KDC detect a service ticket that
was altered before being handed back to it, which matters when a service presents a user's ticket
as evidence in [S4U2Proxy](s4u.md#s4u2proxy-service-for-user-to-proxy)
([MS-SFU &sect;3.2.5.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/20999fbc-f854-4cb1-9240-65c425e529a1)). The extended KDC signature gives the KDC a `krbtgt`-keyed check over
the whole PAC.

!!! warning "The service can only check one of these"
    A service holds its own key and nothing else, so the only signature it can verify by itself
    is the **server signature**. The other three need the `krbtgt` key, which means a domain
    controller has to do the checking.

    Windows has a mechanism for that -- PAC validation, in which the server sends the PAC
    signatures to a domain controller over Netlogon -- but it is the exception, not the rule. Per
    [Microsoft's description of the feature](https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation),
    PAC validation is skipped when the service runs as Local System, Network Service, or Local
    Service, or holds `SeTcbPrivilege` ("Act as part of the operating system"). That covers the
    built-in SMB server and most Windows services. For other processes that run as a service,
    the `ValidateKdcPacSignature` value under
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` decides: when it is `0`,
    "Kerberos does not perform PAC validation on a process that runs as a service", and the same
    article states that "the default value in Windows Server 2008 for this entry is 0".
    [MS-APDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/0926c518-19a2-4981-a1ac-67694f078930)
    says the same of later versions: "Only Windows 2000 Server, Windows XP, and Windows Server
    2003 validate the PAC by default for services." PAC
    validation for a service is therefore something an administrator turns **on** by setting the
    value to `1`; by default it is left to applications that are neither services nor holders
    of `SeTcbPrivilege`.

    The consequence: an attacker who knows a service's long-term key can forge a ticket to that
    service with a PAC of their choosing and a valid server signature -- a
    [Silver Ticket](../attacks/forgery/silver-ticket.md) -- and a service that does not ask a
    domain controller will accept it. The `krbtgt`-keyed signatures only stop the forgery when
    something that holds the `krbtgt` key looks at the ticket.

### PAC Hardening Timeline

The buffers and checks above were added over several years, each in response to a specific
vulnerability:

--8<-- "includes/pac-hardening-timeline.md"

None of these updates makes the KDC look up group membership again during the TGS exchange. The
KDC copies the group SIDs from the TGT's PAC into the service ticket's PAC and adds only the
domain-local groups of the service's domain ([MS-KILE &sect;3.3.5.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2e5dcf34-4b51-44a0-b45a-277ed616ca39)). A change to a user's group
membership therefore takes effect when the user obtains a new TGT, not before.

### KERB_VALIDATION_INFO -- The Authorization Payload

The `KERB_VALIDATION_INFO` structure is the most important part of the PAC. It contains
everything Windows needs to build an access token:

- **User SID** -- e.g., `S-1-5-21-<domain>-1013` (alice's unique security identifier)
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
     KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96 ❸
     Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize  ❹
     Start Time: 4/3/2026 8:00:00 (local)                ❺
     End Time:   4/3/2026 18:00:00 (local)               ❻
     Renew Time: 4/10/2026 8:00:00 (local)               ❼
     Session Key Type: AES-256-CTS-HMAC-SHA1-96           ❽
     Cache Flags: 0x1 -> PRIMARY
     Kdc Called: dc1.corp.local                           ❾

#1>  Client: alice @ CORP.LOCAL
     Server: HTTP/web.corp.local @ CORP.LOCAL
     KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
     Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
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
| 4 | `Ticket Flags` | The TGT has `initial` (issued via AS Exchange) and `pre_authent` (pre-auth was used). The service ticket lacks `initial` because it was issued via the TGS. `name_canonicalize` is how `klist` labels bit 15, which the RFC calls `enc-pa-rep`. |
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
- Up to four PAC signatures protect integrity. A service can verify only the server signature;
  the three `krbtgt`-keyed signatures can be checked only by a domain controller
- The KDC copies group SIDs from the TGT into each service ticket; it does not look them up again

Next: [Pre-Authentication](preauth.md), how the client proves its identity before the KDC issues
a TGT.
