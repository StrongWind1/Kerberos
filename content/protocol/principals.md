---
description: How Kerberos names users, computers, and services in Active Directory - principal name format, realms, sAMAccountName and UPN, computer accounts, and Service Principal Names.
---

# Principals and Realms

Every participant in a Kerberos exchange - whether a user, a computer, or a service - needs a unique identity. Kerberos calls these identities **principals**. Principals live inside administrative boundaries called **realms**. This page explains how naming works and how Active Directory maps its own naming conventions onto the Kerberos model.

---

## Kerberos Principals

A **principal** is any entity that can authenticate using the Kerberos protocol. Per [RFC 4120 &sect;1.7](https://datatracker.ietf.org/doc/html/rfc4120#section-1.7), a principal is "a named client or server entity that participates in a network communication, with one name that is considered canonical."

In practice, principals fall into three categories:

User principals
:   People who log in. Example: `alice@CORP.LOCAL`

Computer principals
:   Computer accounts that represent domain-joined computers. Example: `WORKSTATION1$@CORP.LOCAL`

Service principals
:   Instances of network services that clients authenticate to. Example: `HTTP/web.corp.local@CORP.LOCAL`

---

## Principal Name Format

A Kerberos principal name has the general form:

```
primary/instance@REALM
```

| Component | Description | Example |
|-----------|-------------|---------|
| **primary** | The main identifier. For users, this is the username. For services, this is the service class. | `alice`, `HTTP`, `krbtgt` |
| **instance** | An optional qualifier, separated by `/`. For services, this is typically the hostname. For the `krbtgt` principal, it is the realm name. | `web.corp.local`, `CORP.LOCAL` |
| **REALM** | The administrative domain, separated by `@`. Always uppercase by convention. | `CORP.LOCAL` |

Examples:

| Principal | Type | Description |
|-----------|------|-------------|
| `alice@CORP.LOCAL` | User | Alice's user account |
| `krbtgt/CORP.LOCAL@CORP.LOCAL` | Service | The KDC's own Ticket-Granting Service |
| `HTTP/web.corp.local@CORP.LOCAL` | Service | A web server's HTTP service |
| `WORKSTATION1$@CORP.LOCAL` | Computer | A domain-joined workstation |
| `MSSQLSvc/sql.corp.local:1433@CORP.LOCAL` | Service | SQL Server on a specific port |

---

## Realms

A **realm** is the administrative boundary within which a KDC has authority. The KDC can only issue tickets for principals registered in its own realm (or provide referrals to other realms via trust relationships).

Per [RFC 4120 &sect;6.1](https://datatracker.ietf.org/doc/html/rfc4120#section-6.1), realm names are case-sensitive, and by convention uppercase is used.

In Active Directory, the mapping is straightforward:

!!! info "Realm = Domain (uppercase)"
    The Kerberos realm is the Active Directory DNS domain name, converted to uppercase. Domain `corp.local` becomes realm `CORP.LOCAL`. Domain `engineering.contoso.com` becomes realm `ENGINEERING.CONTOSO.COM`.

A forest with multiple domains has multiple realms. Cross-realm authentication is possible between them through trust relationships, as described on the [Active Directory Components](active-directory.md) page.

---

## User Naming in Active Directory

Active Directory gives each user account several different names. Understanding which name Kerberos uses is important, because it affects login behavior, salt computation for key derivation, and ticket contents.

### sAMAccountName

The **sAMAccountName** is the pre-Windows 2000 login name. It is the name you see in the `DOMAIN\username` format.

- Stored in the `sAMAccountName` attribute
- Maximum length: **20 characters**
- Must be unique **within the domain**
- Mandatory for all user and computer accounts

This is the name that Kerberos actually places in the `cname` (client name) field of tickets. When you examine a TGT or service ticket, the client name inside is the sAMAccountName, not the UPN.

### User Principal Name (UPN)

The **UPN** is the Internet-style login name in the format `user@suffix`.

- Stored in the `userPrincipalName` attribute
- Maximum length: **1024 characters**
- Must be unique **within the forest**
- Optional (the attribute can be empty)

The UPN suffix defaults to the DNS domain name, but administrators can add custom suffixes. For example, a user in domain `corp.internal` might have the UPN `alice@contoso.com` for a cleaner login experience.

### Implicit UPN

Even if the `userPrincipalName` attribute is not set, a user can always log in with the format:

```
sAMAccountName@DnsDomainName
```

This is called the **implicit UPN**. For example, if Alice's sAMAccountName is `alice` and she is in the domain `corp.local`, she can log in as `alice@corp.local` regardless of whether an explicit UPN is configured.

!!! tip "What Kerberos actually uses"
    No matter which login format you type - `CORP\alice`, `alice@corp.local`, or a custom UPN like `alice@contoso.com` - the TGT that comes back always contains the **sAMAccountName** as the client name and the **DNS domain name** (uppercase) as the realm. The login name is resolved to these canonical values during the AS exchange.

### Other Name Forms

Distinguished Name (DN)
:   The full LDAP path to the object. Example: `CN=alice,OU=Users,DC=corp,DC=local`. Not used by Kerberos directly, but useful for LDAP queries.

Security Identifier (SID)
:   A unique binary identifier assigned to every security principal. Example: `S-1-5-21-3623811015-3361044348-30300820-1013`. SIDs appear in the PAC inside Kerberos tickets for authorization purposes but are not used as Kerberos principal names.

---

## Computer Accounts

When a Windows computer joins a domain, Active Directory creates a **computer account** for it. This account is a security principal, just like a user account, and it participates in Kerberos authentication.

Computer account naming:

- sAMAccountName: the computer name with a trailing `$`. Example: `WORKSTATION1$`
- The computer has a password (a long, randomly generated string that the machine manages automatically, rotating every 30 days by default)
- The computer authenticates to the KDC using this password-derived key, just like a user does

When a computer boots and joins the network, it performs an AS exchange to get its own TGT - exactly the same process a user goes through at login.

---

## Service Principal Names (SPNs)

A **Service Principal Name (SPN)** is a unique identifier for a service instance running on a specific host. SPNs are how Kerberos maps a service request to the correct account in Active Directory.

When a client wants to access a service (say, an HTTP web application on `web.corp.local`), it constructs the SPN `HTTP/web.corp.local` and includes it in the TGS request. The KDC searches Active Directory for an account that has this SPN registered in its `servicePrincipalName` attribute, then encrypts the service ticket with that account's secret key.

### SPN Format

Per [MS-KILE &sect;3.1.5.11](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/04033bd5-913c-4c78-a398-b549b09e65d9), SPNs follow this format ([RFC 4120 &sect;6.2.1](https://datatracker.ietf.org/doc/html/rfc4120#section-6.2.1) defines only the underlying two-part server name, a service component followed by a host component):

```
ServiceClass/Host[:Port][/ServiceName]
```

| Component | Required | Description | Example |
|-----------|----------|-------------|---------|
| **ServiceClass** | Yes | The general class of the service | `HTTP`, `MSSQLSvc`, `CIFS` |
| **Host** | Yes | The FQDN (or NetBIOS name) of the server | `web.corp.local` |
| **Port** | No | Non-default port number | `:1433` |
| **ServiceName** | No | Rarely used. Can distinguish service instances. | |

In most cases, SPNs take the simple form `ServiceClass/Host`. The port is only needed when multiple instances of the same service class run on one host with different ports (e.g., multiple SQL Server instances).

### Common Built-in SPNs

Windows automatically registers SPNs for standard services. These are mapped through the **HOST** SPN, which acts as an alias for many service classes:

| SPN Service Class | Service | Notes |
|-------------------|---------|-------|
| `HOST` | General host services | Alias for about fifty built-in service classes, including `cifs`, `http`, `www`, `dns`, `rpcss`, `spooler`, and `schedule` |
| `HTTP` | Web services (IIS, etc.) | Used for both HTTP and HTTPS |
| `CIFS` | File sharing (SMB) | Common Internet File System |
| `LDAP` | Directory services | LDAP queries to a DC |
| `DNS` | DNS server | Registered on DCs running DNS |
| `TERMSRV` | Remote Desktop | Terminal Services / RDP |
| `MSSQLSvc` | SQL Server | Often includes a port number |
| `WSMAN` | WinRM / PowerShell Remoting | Windows Remote Management |
| `krbtgt` | Ticket-Granting Service | Special SPN for the KDC itself |

!!! info "HOST is a catch-all"
    When a computer joins the domain, Windows registers `HOST/<hostname>` and `HOST/<fqdn>` on the computer account. The forest-wide `sPNMappings` attribute (on the `CN=Directory Service` object in the configuration partition) maps HOST to a long list of service classes such as `cifs`, `http`, `www`, `dns`, `rpcss`, and `spooler`, so a single HOST registration covers many standard services. Microsoft's [`setspn` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn) lists the 52 built-in service classes and notes that "a host SPN can substitute for any of the mentioned SPNs". Service classes that are **not** in the default mapping - `ldap`, `TERMSRV`, `WSMAN`, `MSSQLSvc`, and others - are registered as SPNs in their own right, either by the service itself or by an administrator. You also need explicit SPNs for services running under a different account.

### Where SPNs Are Stored

SPNs are stored in the `servicePrincipalName` attribute of the account that runs the service:

- Services running as **Local System, Network Service, or a virtual account** (for example `NT SERVICE\MSSQLSERVER` or an IIS application pool identity) use the computer's identity on the network, so their SPNs are registered on the **computer account** (`WORKSTATION1$`). For virtual accounts, Microsoft's [service accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts) says they "access network resources by using the credentials of the computer account".
- Services running as a **managed service account** (MSA, gMSA, or dMSA) register their SPNs on **that managed account**, which is its own object in AD.
- Services running as a **domain user account** register their SPNs on that **user account**.

One account can have multiple SPNs. For example, a Domain Controller's computer account typically has SPNs for LDAP, DNS, Kerberos, and more.

!!! warning "Duplicate SPNs break Kerberos"
    An SPN must be unique within the forest. If two accounts have the same SPN registered, the KDC cannot determine which account's key to use for encrypting the service ticket. The result is authentication failures. Always check for duplicates before registering a new SPN.

### Managing SPNs with setspn

The `setspn` command-line tool manages SPNs in Active Directory:

```powershell
# List all SPNs registered on an account
setspn -L corp\webserver

# Register a new SPN on an account (-S checks for duplicates first)
setspn -S HTTP/web.corp.local corp\webserver

# Search the entire forest for an SPN
setspn -F -Q HTTP/web.corp.local

# Search for all SPNs matching a pattern
setspn -Q MSSQLSvc/*

# Remove an SPN
setspn -D HTTP/web.corp.local corp\webserver
```

### AD Account Types That Can Bear SPNs

Five Active Directory object types can have `servicePrincipalName` registered:

- **User service accounts** (`user`, objectCategory=person) - manually registered SPNs,
  human-set passwords; the primary Kerberoasting target.
- **Computer accounts** (`computer`) - SPNs registered automatically at domain join;
  passwords auto-rotate every 30 days.
- **gMSA** (`msDS-GroupManagedServiceAccount`) - explicitly registered SPNs;
  240-byte randomly generated, auto-rotating password.
- **MSA** (`msDS-ManagedServiceAccount`) - explicitly registered SPNs; auto-rotating
  password.
- **dMSA** (`msDS-DelegatedManagedServiceAccount`, Server 2025+) - explicitly registered
  SPNs; auto-rotating password.

For the full table of defaults, targets, and GPO coverage per type, see
[SPN-Bearing Account Types](../index.md#spn-bearing-account-types).

!!! tip "Pentester note"
    SPNs registered on **user service accounts** (objectCategory=person) are the viable Kerberoasting targets. Computer accounts, gMSA, MSA, and dMSA all use auto-rotating passwords that are infeasible to crack even if you obtain an RC4-encrypted ticket. Focus enumeration on the LDAP filter `(&(servicePrincipalName=*)(objectCategory=person))` to isolate the actionable targets.

---

## Summary

- A principal is any user, computer, or service that can authenticate; its name has the form `primary/instance@REALM`
- The realm is the AD DNS domain name in uppercase
- Whatever logon name a user types, the ticket carries the sAMAccountName and the realm
- Computers are principals too: they hold a password-derived key and obtain their own TGT
- An SPN maps a service request to the account whose key encrypts the service ticket; it must be unique in the forest
- SPNs live on the account the service runs as - the computer account, a managed service account, or a user account

Next: [Protocol Overview](overview.md), the three exchanges and the keys that tie them together.
