*[AD]: Active Directory
*[AD DS]: Active Directory Domain Services
*[AD CS]: Active Directory Certificate Services
*[KDC]: Key Distribution Center -- the Kerberos authentication engine running on every Domain Controller
*[DC]: Domain Controller
*[TGT]: Ticket-Granting Ticket -- the initial credential issued during the AS exchange
*[TGS]: Ticket-Granting Service -- the KDC component that issues service tickets. Attack tooling also uses "TGS" loosely to mean a service ticket
*[SPN]: Service Principal Name -- unique identifier for a service instance (e.g. HTTP/web.corp.local)
*[PAC]: Privilege Attribute Certificate -- authorization data (SIDs, groups) embedded in Kerberos tickets
*[etype]: Encryption type -- identifies the cipher, integrity check, and key derivation method
*[gMSA]: Group Managed Service Account -- 240-byte randomly generated, auto-rotating password; infeasible to crack
*[RBCD]: Resource-Based Constrained Delegation
*[KCD]: Kerberos Constrained Delegation
*[NTLM]: NT LAN Manager -- legacy authentication protocol, fallback when Kerberos is unavailable
*[SSO]: Single Sign-On
*[GPO]: Group Policy Object
*[ACL]: Access Control List
*[SID]: Security Identifier
*[UPN]: User Principal Name (e.g. alice@corp.local)
*[FQDN]: Fully Qualified Domain Name
*[DFL]: Domain Functional Level
*[PBKDF2]: Password-Based Key Derivation Function 2
*[CTS]: Cipher Text Stealing -- block cipher mode used by AES in Kerberos
*[HMAC]: Hash-based Message Authentication Code
*[LSASS]: Local Security Authority Subsystem Service
*[SSPI]: Security Support Provider Interface
*[SPNEGO]: Simple and Protected GSSAPI Negotiation Mechanism
*[ASN.1]: Abstract Syntax Notation One -- encoding format for Kerberos messages
*[NTP]: Network Time Protocol
*[RODC]: Read-Only Domain Controller
*[IFM]: Install From Media -- offline AD database backup method
*[msDS-SET]: msDS-SupportedEncryptionTypes -- AD attribute declaring which encryption types an account supports
*[DDSET]: DefaultDomainSupportedEncTypes -- registry value on the DC that provides the etype fallback for accounts with msDS-SET = 0
*[AES-SK]: AES Session Key -- bit 5 (0x20) in the etype bitmask; forces AES for session keys even when the ticket body uses RC4
*[AS-REQ]: Authentication Service Request -- the initial Kerberos message requesting a TGT
*[TGS-REQ]: Ticket-Granting Service Request -- the Kerberos message requesting a service ticket using a TGT
*[FAST]: Flexible Authentication Secure Tunneling -- Kerberos armoring that protects the pre-authentication exchange (RFC 6113)
*[MSA]: Managed Service Account -- standalone managed service account bound to one computer, with an auto-rotating password
*[dMSA]: Delegated Managed Service Account -- managed service account type introduced in Windows Server 2025
*[S4U]: Service for User -- the S4U2Self and S4U2Proxy Kerberos extensions behind constrained delegation (MS-SFU)
*[PKINIT]: Public Key Cryptography for Initial Authentication in Kerberos -- certificate or key based pre-authentication (RFC 4556)
*[U2U]: User-to-User -- Kerberos variant in which the service ticket is encrypted with the session key of the target's TGT instead of its long-term key
*[TDO]: Trusted Domain Object -- the AD object that holds a trust's direction, attributes, and trust passwords
*[GC]: Global Catalog -- forest-wide partial replica used to resolve UPNs, universal groups, and SPNs across domains
