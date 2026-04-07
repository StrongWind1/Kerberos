*[AD]: Active Directory
*[AD DS]: Active Directory Domain Services
*[AD CS]: Active Directory Certificate Services
*[KDC]: Key Distribution Center -- the Kerberos authentication engine running on every Domain Controller
*[DC]: Domain Controller
*[TGT]: Ticket-Granting Ticket -- the initial credential issued during the AS exchange
*[TGS]: Ticket-Granting Service -- the KDC component that issues service tickets
*[SPN]: Service Principal Name -- unique identifier for a service instance (e.g. HTTP/web.corp.local)
*[PAC]: Privilege Attribute Certificate -- authorization data (SIDs, groups) embedded in Kerberos tickets
*[etype]: Encryption type -- identifies the cipher, integrity check, and key derivation method
*[gMSA]: Group Managed Service Account -- auto-rotating 240-character password, immune to cracking
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
*[OG]: OpenGraph
*[msDS-SET]: msDS-SupportedEncryptionTypes -- AD attribute declaring which encryption types an account supports
*[DDSET]: DefaultDomainSupportedEncTypes -- registry value on the DC that provides the etype fallback for accounts with msDS-SET = 0
*[AES-SK]: AES Session Key -- bit 5 (0x20) in the etype bitmask; forces AES for session keys even when the ticket body uses RC4
*[AS-REQ]: Authentication Service Request -- the initial Kerberos message requesting a TGT
*[TGS-REQ]: Ticket-Granting Service Request -- the Kerberos message requesting a service ticket using a TGT
*[FAST]: Flexible Authentication Secure Tunneling -- Kerberos armoring that protects the pre-authentication exchange (RFC 6113)
