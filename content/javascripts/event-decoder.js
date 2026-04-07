/**
 * Kerberos Event Decoder — paste raw Windows Security Event XML
 * (4768/4769/4770/4771) and get human-readable field explanations,
 * ticket option flags, encryption type assessments, and security warnings.
 *
 * Pure vanilla JS, no dependencies.  Follows the same IIFE pattern
 * as etype-calculator.js.
 */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /*  Event type metadata                                               */
  /* ------------------------------------------------------------------ */

  var EVENT_TYPES = {
    4768: { name: "TGT Request (AS-REQ)", desc: "A Kerberos authentication ticket (TGT) was requested.", statusField: "Status" },
    4769: { name: "Service Ticket Request (TGS-REQ)", desc: "A Kerberos service ticket was requested.", statusField: "Status" },
    4770: { name: "Service Ticket Renewed", desc: "A Kerberos service ticket was renewed.", statusField: null },
    4771: { name: "Pre-authentication Failed", desc: "Kerberos pre-authentication failed.", statusField: "Status", alwaysFail: true }
  };

  /* ------------------------------------------------------------------ */
  /*  Ticket Options — MSB 0 numbering per RFC 4120 §5.2.8             */
  /*  Bit 0 is the MOST significant bit (0x80000000).                   */
  /*  To test bit N: (value >>> (31 - N)) & 1                          */
  /* ------------------------------------------------------------------ */

  var TICKET_OPTIONS = {
    0: { name: "Reserved", desc: "Reserved for future use." },
    1: { name: "Forwardable", desc: "TGT can be used to obtain forwarded TGTs with different network addresses." },
    2: { name: "Forwarded", desc: "TGT has been forwarded or ticket was issued from a forwarded TGT." },
    3: { name: "Proxiable", desc: "TGT can be used to obtain tickets with different network addresses." },
    4: { name: "Proxy", desc: "Network address in ticket differs from the one in the TGT used to obtain it." },
    5: { name: "Allow-postdate", desc: "Postdating requested (not supported by KILE)." },
    6: { name: "Postdated", desc: "Ticket is postdated (not supported by KILE)." },
    7: { name: "Invalid", desc: "Ticket is invalid and must be validated by the KDC before use." },
    8: { name: "Renewable", desc: "Ticket can be renewed at the KDC periodically." },
    9: { name: "Initial", desc: "Ticket was issued via AS exchange, not from a TGT." },
    10: { name: "Pre-authent", desc: "Client was authenticated by the KDC before ticket issuance." },
    11: { name: "Opt-hardware-auth", desc: "Hardware-assisted pre-authentication (deprecated, should not be set)." },
    12: { name: "Transited-policy-checked", desc: "Transited domain check (KILE ignores this flag)." },
    13: { name: "Ok-as-delegate", desc: "Service account is trusted for delegation." },
    14: { name: "Request-anonymous", desc: "Anonymous ticket requested (not used by KILE)." },
    15: { name: "Name-canonicalize", desc: "Client requested KDC name canonicalization (referrals)." },
    26: { name: "Disable-transited-check", desc: "Disable transited field checking on TGT." },
    27: { name: "Renewable-ok", desc: "Renewable ticket acceptable if requested lifetime unavailable." },
    28: { name: "Enc-tkt-in-skey", desc: "Ticket encrypted in session key (user-to-user)." },
    30: { name: "Renew", desc: "This is a renewal request for an existing ticket." },
    31: { name: "Validate", desc: "Request to validate a postdated ticket." }
  };

  /* ------------------------------------------------------------------ */
  /*  Encryption types — hex code to name and security assessment       */
  /* ------------------------------------------------------------------ */

  /* IANA Kerberos Encryption Type Numbers — https://www.iana.org/assignments/kerberos-parameters
     Last updated 2024-12-06.  Windows-specific notes retained where applicable. */
  var ENCRYPTION_TYPES = {
    0x0: { name: "reserved", security: "reserved", note: "RFC 6448" },
    0x1: { name: "DES-CBC-CRC", security: "removed", note: "Deprecated (RFC 6649), removed in Server 2025" },
    0x2: { name: "DES-CBC-MD4", security: "deprecated", note: "Deprecated (RFC 6649)" },
    0x3: { name: "DES-CBC-MD5", security: "removed", note: "Deprecated (RFC 6649), removed in Server 2025" },
    0x4: { name: "reserved", security: "reserved", note: "RFC 3961" },
    0x5: { name: "DES3-CBC-MD5", security: "deprecated", note: "Deprecated (RFC 8429)" },
    0x6: { name: "reserved", security: "reserved", note: "RFC 3961" },
    0x7: { name: "DES3-CBC-SHA1", security: "deprecated", note: "Deprecated (RFC 8429)" },
    0x9: { name: "dsaWithSHA1-CmsOID", security: "informational", note: "PKINIT CMS (RFC 4556)" },
    0xA: { name: "md5WithRSAEncryption-CmsOID", security: "informational", note: "PKINIT CMS (RFC 4556)" },
    0xB: { name: "sha1WithRSAEncryption-CmsOID", security: "informational", note: "PKINIT CMS (RFC 4556)" },
    0xC: { name: "rc2CBC-EnvOID", security: "informational", note: "PKINIT CMS (RFC 4556)" },
    0xD: { name: "rsaEncryption-EnvOID", security: "informational", note: "PKINIT CMS (RFC 4556, PKCS#1 v1.5)" },
    0xE: { name: "rsaES-OAEP-ENV-OID", security: "informational", note: "PKINIT CMS (RFC 4556, PKCS#1 v2.0)" },
    0xF: { name: "des-ede3-cbc-Env-OID", security: "informational", note: "PKINIT CMS (RFC 4556)" },
    0x10: { name: "DES3-CBC-SHA1-KD", security: "deprecated", note: "Deprecated (RFC 8429)" },
    0x11: { name: "AES128-CTS-HMAC-SHA1-96", security: "recommended", note: "RFC 3962" },
    0x12: { name: "AES256-CTS-HMAC-SHA1-96", security: "recommended", note: "RFC 3962" },
    0x13: { name: "AES128-CTS-HMAC-SHA256-128", security: "recommended", note: "RFC 8009" },
    0x14: { name: "AES256-CTS-HMAC-SHA384-192", security: "recommended", note: "RFC 8009" },
    0x17: { name: "RC4-HMAC", security: "deprecated", note: "Deprecated (RFC 8429) - Off by default July 2026" },
    0x18: { name: "RC4-HMAC-EXP", security: "deprecated", note: "Deprecated (RFC 6649), export-grade" },
    0x19: { name: "CAMELLIA128-CTS-CMAC", security: "informational", note: "RFC 6803" },
    0x1A: { name: "CAMELLIA256-CTS-CMAC", security: "informational", note: "RFC 6803" },
    0x41: { name: "subkey-keymaterial", security: "informational", note: "Opaque (PacketCable)" },
    0xFFFFFFFF: { name: "(Failure)", security: "error", note: "Shown in audit failure events" }
  };

  /* ------------------------------------------------------------------ */
  /*  Result / failure codes — RFC 4120 §7.5.9                         */
  /* ------------------------------------------------------------------ */

  var RESULT_CODES = {
    0x0: { name: "KDC_ERR_NONE", desc: "No error", causes: "" },
    0x1: { name: "KDC_ERR_NAME_EXP", desc: "Client's entry in KDC database has expired", causes: "" },
    0x2: { name: "KDC_ERR_SERVICE_EXP", desc: "Server's entry in KDC database has expired", causes: "" },
    0x3: { name: "KDC_ERR_BAD_PVNO", desc: "Requested Kerberos version number not supported", causes: "" },
    0x4: { name: "KDC_ERR_C_OLD_MAST_KVNO", desc: "Client's key encrypted in old master key", causes: "" },
    0x5: { name: "KDC_ERR_S_OLD_MAST_KVNO", desc: "Server's key encrypted in old master key", causes: "" },
    0x6: { name: "KDC_ERR_C_PRINCIPAL_UNKNOWN", desc: "Client not found in Kerberos database", causes: "The username doesn't exist." },
    0x7: { name: "KDC_ERR_S_PRINCIPAL_UNKNOWN", desc: "Server not found in Kerberos database", causes: "Server name not found in Active Directory." },
    0x8: { name: "KDC_ERR_PRINCIPAL_NOT_UNIQUE", desc: "Multiple principal entries in KDC database", causes: "Duplicate principal names exist. Check for duplicate SPNs." },
    0x9: { name: "KDC_ERR_NULL_KEY", desc: "Client or server has a null key", causes: "Reset the password on the account." },
    0xA: { name: "KDC_ERR_CANNOT_POSTDATE", desc: "Ticket not eligible for postdating", causes: "Client requested postdating, or time difference between client and KDC." },
    0xB: { name: "KDC_ERR_NEVER_VALID", desc: "Requested start time is later than end time", causes: "Time difference between KDC and client." },
    0xC: { name: "KDC_ERR_POLICY", desc: "KDC policy rejects request", causes: "Logon restrictions: workstation restriction, smart card requirement, or logon time restriction." },
    0xD: { name: "KDC_ERR_BADOPTION", desc: "KDC cannot accommodate requested option", causes: "TGT expiring, or SPN not in Allowed-to-delegate-to list." },
    0xE: { name: "KDC_ERR_ETYPE_NOTSUPP", desc: "KDC has no support for encryption type", causes: "Client and KDC have no common encryption type. Check msDS-SupportedEncryptionTypes and GPO settings." },
    0xF: { name: "KDC_ERR_SUMTYPE_NOSUPP", desc: "KDC has no support for checksum type", causes: "No key of the appropriate encryption type available." },
    0x10: { name: "KDC_ERR_PADATA_TYPE_NOSUPP", desc: "KDC has no support for PADATA type", causes: "Smart card certificate not found, or wrong CA. Check domain controller certificate." },
    0x11: { name: "KDC_ERR_TRTYPE_NO_SUPP", desc: "KDC has no support for transited type", causes: "" },
    0x12: { name: "KDC_ERR_CLIENT_REVOKED", desc: "Client's credentials have been revoked", causes: "Account disabled, expired, or locked out." },
    0x13: { name: "KDC_ERR_SERVICE_REVOKED", desc: "Credentials for server have been revoked", causes: "" },
    0x14: { name: "KDC_ERR_TGT_REVOKED", desc: "TGT has been revoked", causes: "Remote KDC changed its PKCROSS key." },
    0x15: { name: "KDC_ERR_CLIENT_NOTYET", desc: "Client not yet valid", causes: "" },
    0x16: { name: "KDC_ERR_SERVICE_NOTYET", desc: "Server not yet valid", causes: "" },
    0x17: { name: "KDC_ERR_KEY_EXPIRED", desc: "Password has expired", causes: "The user's password has expired." },
    0x18: { name: "KDC_ERR_PREAUTH_FAILED", desc: "Pre-authentication information was invalid", causes: "Wrong password provided." },
    0x19: { name: "KDC_ERR_PREAUTH_REQUIRED", desc: "Additional pre-authentication required", causes: "Normal for MIT-Kerberos clients that don't send pre-auth initially." },
    0x1A: { name: "KDC_ERR_SERVER_NOMATCH", desc: "KDC does not know about the requested server", causes: "" },
    0x1D: { name: "KDC_ERR_SVC_UNAVAILABLE", desc: "KDC is unavailable", causes: "" },
    0x1F: { name: "KRB_AP_ERR_BAD_INTEGRITY", desc: "Integrity check on decrypted field failed", causes: "Authenticator encrypted with wrong session key. Possible attack or network noise." },
    0x20: { name: "KRB_AP_ERR_TKT_EXPIRED", desc: "The ticket has expired", causes: "Normal for short-lived tickets. Renewal is automatic." },
    0x21: { name: "KRB_AP_ERR_TKT_NYV", desc: "The ticket is not yet valid", causes: "Clock skew between KDC and client or cross-realm time sync issue." },
    0x22: { name: "KRB_AP_ERR_REPEAT", desc: "The request is a replay", causes: "Duplicate authenticator detected by KDC." },
    0x23: { name: "KRB_AP_ERR_NOT_US", desc: "The ticket is not for us", causes: "Ticket meant for a different realm." },
    0x24: { name: "KRB_AP_ERR_BADMATCH", desc: "Ticket and authenticator do not match", causes: "KRB_TGS_REQ sent to wrong KDC, or account mismatch during protocol transition." },
    0x25: { name: "KRB_AP_ERR_SKEW", desc: "Clock skew is too great", causes: "Client/server time difference exceeds tolerance (default 5 minutes). Sync clocks with NTP." },
    0x26: { name: "KRB_AP_ERR_BADADDR", desc: "Network address doesn't match address in ticket", causes: "IP address changed, or ticket passed through proxy/NAT." },
    0x27: { name: "KRB_AP_ERR_BADVERSION", desc: "Protocol version numbers don't match", causes: "KRB_SAFE message version mismatch." },
    0x28: { name: "KRB_AP_ERR_MSG_TYPE", desc: "Message type is unsupported", causes: "Wrong message format or UDP used with User-to-User auth." },
    0x29: { name: "KRB_AP_ERR_MODIFIED", desc: "Message stream modified and checksum didn't match", causes: "Wrong encryption key, data modified in transit, DNS misconfiguration, or stale DNS cache." },
    0x2A: { name: "KRB_AP_ERR_BADORDER", desc: "Message out of order", causes: "Incorrect sequence number in KRB_SAFE or KRB_PRIV message." },
    0x2C: { name: "KRB_AP_ERR_BADKEYVER", desc: "Specified version of key isn't available", causes: "Ticket uses an old key version the server no longer has." },
    0x2D: { name: "KRB_AP_ERR_NOKEY", desc: "Service key not available", causes: "Server doesn't have the proper key for the ticket's realm." },
    0x2E: { name: "KRB_AP_ERR_MUT_FAIL", desc: "Mutual authentication failed", causes: "" },
    0x2F: { name: "KRB_AP_ERR_BADDIRECTION", desc: "Incorrect message direction", causes: "" },
    0x30: { name: "KRB_AP_ERR_METHOD", desc: "Alternative authentication method required", causes: "Obsolete per RFC 4120." },
    0x31: { name: "KRB_AP_ERR_BADSEQ", desc: "Incorrect sequence number in message", causes: "" },
    0x32: { name: "KRB_AP_ERR_INAPP_CKSUM", desc: "Inappropriate type of checksum in message", causes: "Checksum not collision-proof, or checksums don't match." },
    0x33: { name: "KRB_AP_PATH_NOT_ACCEPTED", desc: "Desired path is unreachable", causes: "" },
    0x34: { name: "KRB_ERR_RESPONSE_TOO_BIG", desc: "Too much data", causes: "Ticket too large for UDP. Windows automatically retries with TCP." },
    0x3C: { name: "KRB_ERR_GENERIC", desc: "Generic error", causes: "Group membership overloaded PAC, recent password changes not propagated, SPN too long, or crypto subsystem error." },
    0x3D: { name: "KRB_ERR_FIELD_TOOLONG", desc: "Field is too long for this implementation", causes: "Request length exceeds 4-octet encoding limit." },
    0x3E: { name: "KDC_ERR_CLIENT_NOT_TRUSTED", desc: "The client trust failed or isn't implemented", causes: "Smart card certificate revoked or root CA not trusted by DC." },
    0x3F: { name: "KDC_ERR_KDC_NOT_TRUSTED", desc: "The KDC server trust failed or could not be verified", causes: "KDC has no certificate signed by any trustedCertifiers." },
    0x40: { name: "KDC_ERR_INVALID_SIG", desc: "The signature is invalid", causes: "PKI trust exists but client signature on AuthPack (TGT request) verification failed." },
    0x41: { name: "KDC_ERR_KEY_TOO_WEAK", desc: "A higher encryption level is needed", causes: "Diffie-Hellman parameters too weak for expected encryption type." },
    0x42: { name: "KRB_AP_ERR_USER_TO_USER_REQUIRED", desc: "User-to-user authorization is required", causes: "Service requires user-to-user authentication." },
    0x43: { name: "KRB_AP_ERR_NO_TGT", desc: "No TGT was presented or available", causes: "Service doesn't possess a TGT for user-to-user auth." },
    0x44: { name: "KDC_ERR_WRONG_REALM", desc: "Incorrect domain or principal", causes: "Cross-realm TGT presented to wrong realm. Check DNS configuration." }
  };

  /* ------------------------------------------------------------------ */
  /*  Pre-authentication types                                          */
  /* ------------------------------------------------------------------ */

  var PREAUTH_TYPES = {
    0: { name: "(None)", desc: "Logon without pre-authentication", warning: true },
    2: { name: "PA-ENC-TIMESTAMP", desc: "Standard password authentication" },
    11: { name: "PA-ETYPE-INFO", desc: "KDC hints for encryption key selection" },
    15: { name: "PA-PK-AS-REP_OLD", desc: "Smart card logon authentication" },
    16: { name: "PA-PK-AS-REQ", desc: "Smart card authentication request" },
    17: { name: "PA-PK-AS-REP", desc: "Smart card authentication reply" },
    19: { name: "PA-ETYPE-INFO2", desc: "KDC hints for encryption key selection (v2)" },
    20: { name: "PA-SVR-REFERRAL-INFO", desc: "KDC referral ticket" },
    138: { name: "PA-ENCRYPTED-CHALLENGE", desc: "Kerberos Armoring (FAST) \u2014 Server 2012+" }
  };

  /* ------------------------------------------------------------------ */
  /*  Human-readable field labels                                       */
  /* ------------------------------------------------------------------ */

  var FIELD_LABELS = {
    TargetUserName: "Account Name",
    TargetDomainName: "Account Domain",
    TargetSid: "Account SID",
    ServiceName: "Service Name",
    ServiceSid: "Service SID",
    TicketOptions: "Ticket Options",
    Status: "Result Code",
    TicketEncryptionType: "Ticket Encryption Type",
    PreAuthType: "Pre-Authentication Type",
    IpAddress: "Client Address",
    IpPort: "Client Port",
    CertIssuerName: "Certificate Issuer",
    CertSerialNumber: "Certificate Serial Number",
    CertThumbprint: "Certificate Thumbprint",
    LogonGuid: "Logon GUID",
    TransmittedServices: "Transmitted Services",
    ResponseTicket: "Response Ticket Hash",
    RequestTicketHash: "Request Ticket Hash",
    ResponseTicketHash: "Response Ticket Hash",
    AccountSupportedEncryptionTypes: "Account msDS-SupportedEncTypes",
    AccountAvailableKeys: "Account Available Keys",
    ServiceSupportedEncryptionTypes: "Service msDS-SupportedEncTypes",
    ServiceAvailableKeys: "Service Available Keys",
    DCSupportedEncryptionTypes: "DC msDS-SupportedEncTypes",
    DCAvailableKeys: "DC Available Keys",
    ClientAdvertizedEncryptionTypes: "Client Advertised Etypes",
    SessionKeyEncryptionType: "Session Key Encryption Type",
    PreAuthEncryptionType: "Pre-Auth Encryption Type"
  };

  /* ------------------------------------------------------------------ */
  /*  Field source descriptions — where each value comes from and how   */
  /*  a sysadmin can change it.                                         */
  /* ------------------------------------------------------------------ */

  var FIELD_SOURCES = {
    TicketEncryptionType: "Output of etype negotiation. Determined by intersection of client offer, service msDS-SET, and KDC GPO filter.",
    SessionKeyEncryptionType: "Etype for the session key shared between client and service. Influenced by the AES-SK bit (0x20) in DefaultDomainSupportedEncTypes or per-account msDS-SET.",
    PreAuthEncryptionType: "Etype used for the pre-authentication exchange. Driven by client advertised etypes and which keys exist for the account in AD.",
    PreAuthType: "Pre-auth method used. Type 0 means the account has \"Do not require Kerberos preauthentication\" enabled in AD (UAC flag 0x400000).",
    AccountSupportedEncryptionTypes: "Read from the requesting account's msDS-SupportedEncryptionTypes attribute in AD. Set via Set-ADUser/Set-ADComputer, or auto-set by GPO on computer accounts. Value 0 or N/A means DDSET fallback is used.",
    AccountAvailableKeys: "Key types that exist in AD for this account. AES keys require DFL 2008+ and at least one password rotation since DFL upgrade.",
    ServiceSupportedEncryptionTypes: "Read from the target service account's msDS-SupportedEncryptionTypes attribute in AD. Set via Set-ADUser/Set-ADComputer, or auto-set by GPO on computer accounts.",
    ServiceAvailableKeys: "Key types that exist in AD for the service account. AES keys require DFL 2008+ and at least one password rotation.",
    DCSupportedEncryptionTypes: "Read from the DC's own computer account msDS-SupportedEncryptionTypes in AD (not the registry value). Auto-set by the DC's \"Configure encryption types allowed for Kerberos\" GPO (high bits stripped).",
    DCAvailableKeys: "Key types that exist in AD for the DC account. Generated during password rotation and DCPROMO.",
    ClientAdvertizedEncryptionTypes: "Etype list from the wire protocol (AS-REQ/TGS-REQ). Controlled by the client machine's GPO \"Configure encryption types allowed for Kerberos\" (registry: Policies\\...\\Kerberos\\Parameters\\SupportedEncryptionTypes).",
    Status: "Result code from the KDC. 0x0 = success. Non-zero codes indicate why the request was rejected.",
    TicketOptions: "Flags set by the client in the KRB_KDC_REQ. These are protocol-level options, not directly admin-configurable."
  };

  /* ------------------------------------------------------------------ */
  /*  Example events (sanitized from lab captures)                      */
  /* ------------------------------------------------------------------ */

  var EXAMPLES = {
    "4768-success": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4768</EventID><Version>2</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T07:46:35.1028890Z"/><EventRecordID>1620174</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="3292"/><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">DC01$</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1000</Data><Data Name="ServiceName">krbtgt</Data><Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-502</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x0</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="PreAuthType">2</Data><Data Name="IpAddress">::1</Data><Data Name="IpPort">0</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data><Data Name="ResponseTicket">JSZ+Dc/2Ceg79NIeg1Mrsfr8G6Fja12Iw7s3rA6Hmps=</Data><Data Name="AccountSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="AccountAvailableKeys">AES-SHA1, RC4</Data><Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data><Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="DCAvailableKeys">AES-SHA1, RC4</Data><Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 RC4-HMAC-NT RC4-HMAC-OLD RC4-MD4 RC4-HMAC-NT-EXP RC4-HMAC-OLD-EXP</Data><Data Name="SessionKeyEncryptionType">0x12</Data><Data Name="PreAuthEncryptionType">0x12</Data></EventData></Event>',

    "4769-success": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4769</EventID><Version>2</Version><Level>0</Level><Task>14337</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T07:58:08.1119718Z"/><EventRecordID>1620180</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="3440"/><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">Administrator@CONTOSO.LOCAL</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="ServiceName">DC01$</Data><Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-1000</Data><Data Name="TicketOptions">0x40800000</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="IpAddress">::1</Data><Data Name="IpPort">0</Data><Data Name="Status">0x0</Data><Data Name="LogonGuid">{720ea3d8-ae63-d21b-b632-df542dabc526}</Data><Data Name="TransmittedServices">-</Data><Data Name="RequestTicketHash">nl2eYuAWS0zaoVpOBWmRgnqdG073o8wvUsGRmW9mK0k=</Data><Data Name="ResponseTicketHash">OoEgyfNwjVFs7llZ4x+4YoDn+xt68h7IgeunTRd3jlk=</Data><Data Name="AccountSupportedEncryptionTypes">N/A</Data><Data Name="AccountAvailableKeys">N/A</Data><Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data><Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="DCAvailableKeys">AES-SHA1, RC4</Data><Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 RC4-HMAC-NT DES-CBC-MD5 DES-CBC-CRC RC4-HMAC-NT-EXP RC4-HMAC-OLD-EXP</Data><Data Name="SessionKeyEncryptionType">0x12</Data></EventData></Event>',

    "4771-failure": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4771</EventID><Version>0</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-04-07T06:00:54.0797513Z"/><EventRecordID>1619024</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1248"/><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-500</Data><Data Name="ServiceName">krbtgt/CONTOSO</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x18</Data><Data Name="PreAuthType">2</Data><Data Name="IpAddress">::ffff:10.0.0.100</Data><Data Name="IpPort">51032</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data></EventData></Event>',

    "4770-renew": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4770</EventID><Version>0</Version><Level>0</Level><Task>14337</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T03:26:23.4665529Z"/><EventRecordID>166481</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1084"/><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">WIN10$@CONTOSO.LOCAL</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="ServiceName">krbtgt</Data><Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-502</Data><Data Name="TicketOptions">0x2</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="IpAddress">::ffff:10.0.0.100</Data><Data Name="IpPort">49964</Data></EventData></Event>',

    "4768-failure": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4768</EventID><Version>0</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-04-07T08:15:42.3281200Z"/><EventRecordID>166750</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1496"/><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">nonexistent</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="TargetSid">S-1-0-0</Data><Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data><Data Name="ServiceSid">S-1-0-0</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x6</Data><Data Name="TicketEncryptionType">0xffffffff</Data><Data Name="PreAuthType">0</Data><Data Name="IpAddress">::ffff:10.0.0.100</Data><Data Name="IpPort">49273</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data></EventData></Event>'
  };

  /* ------------------------------------------------------------------ */
  /*  State                                                             */
  /* ------------------------------------------------------------------ */

  var root;

  function q(sel) { return root ? root.querySelector(sel) : null; }
  function qa(sel) { return root ? root.querySelectorAll(sel) : []; }

  /* ------------------------------------------------------------------ */
  /*  XML parsing                                                       */
  /* ------------------------------------------------------------------ */

  /**
   * Clean common copy-paste artifacts from event XML before parsing.
   * Handles BOM, CRLF, Event Viewer tree-view "- " prefixes, and
   * leading/trailing whitespace.
   */
  function cleanXml(raw) {
    var s = raw.replace(/^\uFEFF/, "");
    s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    /* Event Viewer tree copy sometimes prefixes lines with "- " */
    s = s.replace(/^- /gm, "");
    s = s.trim();
    /* If there are multiple <Event> blocks, keep only the first */
    var secondEvent = s.indexOf("<Event", 1);
    if (secondEvent > 0) s = s.substring(0, s.indexOf("</Event>") + 8);
    return s;
  }

  /**
   * Parse event XML and return a structured object.
   * Returns: { eventId, version, time, computer, fields: {key: value} }
   * Throws a string message on invalid input.
   */
  function parseEventXml(raw) {
    var xml = cleanXml(raw);
    if (!xml || xml.indexOf("<") === -1) {
      throw "Input does not appear to be XML. In Event Viewer, right-click an event and choose Copy > Copy details as XML.";
    }

    var parser = new DOMParser();
    var doc = parser.parseFromString(xml, "text/xml");
    var err = doc.querySelector("parsererror");
    if (err) {
      throw "Invalid XML: " + (err.textContent || "parse error").substring(0, 200);
    }

    /* Extract System metadata.  Use local-name() to ignore namespace. */
    function getText(parent, localName) {
      var els = parent.getElementsByTagName(localName);
      /* Fallback: try with namespace-aware getElementsByTagNameNS */
      if (els.length === 0) {
        els = parent.getElementsByTagNameNS("*", localName);
      }
      return els.length > 0 ? (els[0].textContent || "") : "";
    }
    function getAttr(parent, localName, attr) {
      var els = parent.getElementsByTagName(localName);
      if (els.length === 0) els = parent.getElementsByTagNameNS("*", localName);
      return els.length > 0 ? (els[0].getAttribute(attr) || "") : "";
    }

    var eventIdStr = getText(doc, "EventID");
    var eventId = parseInt(eventIdStr, 10);
    if (!EVENT_TYPES[eventId]) {
      throw "Unsupported event ID: " + eventIdStr + ". This decoder supports Kerberos events 4768, 4769, 4770, and 4771.";
    }

    var version = parseInt(getText(doc, "Version"), 10) || 0;
    var time = getAttr(doc, "TimeCreated", "SystemTime") || "";
    var computer = getText(doc, "Computer");

    /* Extract EventData fields */
    var fields = {};
    var fieldOrder = [];
    var dataEls = doc.getElementsByTagName("Data");
    if (dataEls.length === 0) dataEls = doc.getElementsByTagNameNS("*", "Data");
    for (var i = 0; i < dataEls.length; i++) {
      var name = dataEls[i].getAttribute("Name");
      if (name) {
        var val = (dataEls[i].textContent || "").trim();
        fields[name] = val;
        fieldOrder.push(name);
      }
    }

    return {
      eventId: eventId,
      version: version,
      time: time,
      computer: computer,
      fields: fields,
      fieldOrder: fieldOrder
    };
  }

  /* ------------------------------------------------------------------ */
  /*  Field decoders                                                    */
  /* ------------------------------------------------------------------ */

  /** Parse a hex string (with or without 0x prefix) to an unsigned integer. */
  function parseHex(s) {
    if (!s) return NaN;
    s = s.replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-fA-F]+$/.test(s)) return NaN;
    return parseInt(s, 16);
  }

  /**
   * Decode TicketOptions hex string to an array of set flag objects.
   * Uses MSB 0 numbering: bit N is tested by (value >>> (31 - N)) & 1.
   */
  function decodeTicketOptions(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return [];
    val = val >>> 0;
    var flags = [];
    for (var bit = 0; bit < 32; bit++) {
      if (((val >>> (31 - bit)) & 1) === 1 && TICKET_OPTIONS[bit]) {
        flags.push({ bit: bit, name: TICKET_OPTIONS[bit].name, desc: TICKET_OPTIONS[bit].desc });
      }
    }
    return flags;
  }

  /** Decode encryption type hex to {name, security, note}. */
  function decodeEncryptionType(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return { name: hexStr || "-", security: "unknown", note: "" };
    /* Handle both 0xFFFFFFFF representations */
    val = val >>> 0;
    if (val === 0xFFFFFFFF) return ENCRYPTION_TYPES[0xFFFFFFFF];
    return ENCRYPTION_TYPES[val] || { name: "Unknown (0x" + val.toString(16).toUpperCase() + ")", security: "unknown", note: "" };
  }

  /** Decode result/status code hex to {name, desc, causes}. */
  function decodeResultCode(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return { name: hexStr || "-", desc: "", causes: "" };
    return RESULT_CODES[val] || { name: "Unknown error (0x" + val.toString(16).toUpperCase() + ")", desc: "", causes: "" };
  }

  /** Decode pre-authentication type (decimal string) to {name, desc}. */
  function decodePreAuthType(decStr) {
    var val = parseInt(decStr, 10);
    if (isNaN(val)) return { name: decStr || "-", desc: "" };
    return PREAUTH_TYPES[val] || { name: "Unknown type (" + val + ")", desc: "" };
  }

  /** Clean IPv6-mapped IPv4 addresses for readability. */
  function cleanIpAddress(addr) {
    if (!addr) return "-";
    var match = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (match) return match[1] + " (IPv4-mapped)";
    if (addr === "::1") return "::1 (localhost)";
    return addr;
  }

  /* ------------------------------------------------------------------ */
  /*  Security warnings engine                                          */
  /* ------------------------------------------------------------------ */

  function generateWarnings(parsed) {
    var w = [];
    var f = parsed.fields;

    /* Check all encryption type fields for weak algorithms */
    var etypeFields = ["TicketEncryptionType", "SessionKeyEncryptionType", "PreAuthEncryptionType"];
    etypeFields.forEach(function (key) {
      if (!f[key]) return;
      var val = parseHex(f[key]);
      if (val === 0x1 || val === 0x3) {
        w.push("DES encryption detected in " + (FIELD_LABELS[key] || key) + ". DES is removed in Windows Server 2025 and should not be in use.");
      }
      if (val === 0x17 || val === 0x18) {
        w.push("RC4 encryption detected in " + (FIELD_LABELS[key] || key) + ". RC4-HMAC is deprecated and will be permanently disabled in July 2026.");
      }
    });

    /* Check client advertised etypes for weak algorithms */
    if (f.ClientAdvertizedEncryptionTypes) {
      var adv = f.ClientAdvertizedEncryptionTypes;
      if (/DES-CBC/i.test(adv)) {
        w.push("Client is advertising DES encryption support. Remove DES from the client's Kerberos encryption policy.");
      }
    }

    /* Pre-authentication type 0 = no pre-auth */
    if (f.PreAuthType === "0") {
      w.push('No pre-authentication was used (PreAuthType=0). Verify the account does not have "Do not require Kerberos preauthentication" enabled.');
    }

    /* Specific failure code guidance */
    if (f.Status) {
      var statusVal = parseHex(f.Status);
      if (statusVal === 0x18) {
        w.push("Status 0x18 (KDC_ERR_PREAUTH_FAILED): Wrong password. If repeated, this may indicate a brute-force attack.");
      }
      if (statusVal === 0x25) {
        w.push("Status 0x25 (KRB_AP_ERR_SKEW): Clock skew exceeded tolerance. Ensure all machines sync time via NTP to the same source.");
      }
      if (statusVal === 0xE) {
        w.push("Status 0xE (KDC_ERR_ETYPE_NOTSUPP): No common encryption type. Check msDS-SupportedEncryptionTypes on both client and service accounts, and verify the GPO Kerberos encryption policy.");
      }
      if (statusVal === 0x6) {
        w.push("Status 0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN): The account does not exist. Verify the username and domain.");
      }
      if (statusVal === 0x12) {
        w.push("Status 0x12 (KDC_ERR_CLIENT_REVOKED): Account is disabled, expired, or locked out. Check the account status in AD.");
      }
    }

    /* v2 events: check if SupportedEncryptionTypes lack AES */
    var setFields = ["AccountSupportedEncryptionTypes", "ServiceSupportedEncryptionTypes", "DCSupportedEncryptionTypes"];
    setFields.forEach(function (key) {
      if (!f[key] || f[key] === "N/A") return;
      var hexMatch = f[key].match(/^(0x[0-9a-fA-F]+)/);
      if (hexMatch) {
        var setVal = parseHex(hexMatch[1]);
        if (!isNaN(setVal) && setVal !== 0 && (setVal & 0x18) === 0) {
          w.push((FIELD_LABELS[key] || key) + " has no AES bits set (value " + hexMatch[1] + "). This account will fail authentication if RC4 is blocked.");
        }
      }
    });

    return w;
  }

  /* ------------------------------------------------------------------ */
  /*  Rendering helpers                                                 */
  /* ------------------------------------------------------------------ */

  /** Create a DOM element with optional class and text content. */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  /** Map etype security level to badge CSS class suffix. */
  function etypeBadgeClass(security) {
    switch (security) {
      case "removed": return "evdec-badge--removed";
      case "deprecated": return "evdec-badge--deprecated";
      case "recommended": return "evdec-badge--recommended";
      case "error": return "evdec-badge--error";
      default: return "evdec-badge--neutral";
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Main rendering                                                    */
  /* ------------------------------------------------------------------ */

  /** Stash the last parsed result so the copy button can access it. */
  var lastParsed = null;

  function render(parsed) {
    lastParsed = parsed;
    var resultsEl = q("#evdec-results");
    var headerEl = q("#evdec-header");
    var warningsEl = q("#evdec-warnings");
    var fieldsEl = q("#evdec-fields");
    var ticketOptsEl = q("#evdec-ticket-options");
    var actionsEl = q("#evdec-result-actions");
    if (!resultsEl || !headerEl || !warningsEl || !fieldsEl || !ticketOptsEl) return;

    if (actionsEl) actionsEl.style.display = "flex";

    /* --- Header --- */
    headerEl.innerHTML = "";
    var meta = EVENT_TYPES[parsed.eventId];

    var headerRow = el("div", "evdec-header-row");

    var badge = el("span", "evdec-event-badge", String(parsed.eventId));
    headerRow.appendChild(badge);

    var titleWrap = el("div", "evdec-header-title");
    titleWrap.appendChild(el("span", "evdec-event-name", meta.name));
    titleWrap.appendChild(el("span", "evdec-event-desc", meta.desc));
    headerRow.appendChild(titleWrap);

    /* Success / failure status */
    var isSuccess = true;
    if (meta.alwaysFail) {
      isSuccess = false;
    } else if (meta.statusField && parsed.fields[meta.statusField]) {
      isSuccess = parseHex(parsed.fields[meta.statusField]) === 0;
    }
    var statusPill = el("span",
      isSuccess ? "evdec-status evdec-status--success" : "evdec-status evdec-status--failure",
      isSuccess ? "Success" : "Failure"
    );
    headerRow.appendChild(statusPill);

    headerEl.appendChild(headerRow);

    /* Timestamp + computer */
    if (parsed.time || parsed.computer) {
      var metaLine = el("div", "evdec-header-meta");
      if (parsed.time) {
        var t = parsed.time.replace("T", " ").replace("Z", " UTC").replace(/\.(\d{3})\d*/, ".$1");
        metaLine.appendChild(el("span", "evdec-meta-item", t));
      }
      if (parsed.computer) {
        metaLine.appendChild(el("span", "evdec-meta-item", parsed.computer));
      }
      headerEl.appendChild(metaLine);
    }

    /* --- Warnings --- */
    var warnings = generateWarnings(parsed);
    warningsEl.innerHTML = "";
    if (warnings.length > 0) {
      warningsEl.style.display = "block";
      warnings.forEach(function (msg) {
        var item = el("div", "evdec-warning-item", msg);
        warningsEl.appendChild(item);
      });
    } else {
      warningsEl.style.display = "none";
    }

    /* --- Etype negotiation pipeline (v2 events with etype fields) --- */
    renderPipeline(parsed);

    /* --- Fields table --- */
    fieldsEl.innerHTML = "";
    var table = el("table", "evdec-table");
    var thead = el("thead");
    var headRow = el("tr");
    headRow.appendChild(el("th", null, "Field"));
    headRow.appendChild(el("th", null, "Raw Value"));
    headRow.appendChild(el("th", null, "Decoded"));
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el("tbody");
    parsed.fieldOrder.forEach(function (key) {
      var val = parsed.fields[key];
      var tr = el("tr");
      tr.appendChild(el("td", "evdec-field-name", FIELD_LABELS[key] || key));

      var rawTd = el("td", "evdec-field-raw");
      var rawCode = el("code", null, val || "-");
      rawTd.appendChild(rawCode);
      tr.appendChild(rawTd);

      var decodedTd = el("td", "evdec-field-decoded");
      renderDecodedValue(decodedTd, key, val, parsed);
      if (FIELD_SOURCES[key]) {
        decodedTd.appendChild(el("div", "evdec-field-source", FIELD_SOURCES[key]));
      }
      tr.appendChild(decodedTd);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    fieldsEl.appendChild(table);

    /* --- Ticket Options breakdown --- */
    ticketOptsEl.innerHTML = "";
    if (parsed.fields.TicketOptions) {
      var flags = decodeTicketOptions(parsed.fields.TicketOptions);
      if (flags.length > 0) {
        ticketOptsEl.style.display = "block";
        ticketOptsEl.appendChild(el("h3", "evdec-section-title", "Ticket Options Breakdown"));
        var flagList = el("div", "evdec-flag-list");
        flags.forEach(function (f) {
          var item = el("div", "evdec-flag-item");
          item.appendChild(el("span", "evdec-flag-bit", "Bit " + f.bit));
          item.appendChild(el("span", "evdec-flag-name", f.name));
          item.appendChild(el("span", "evdec-flag-desc", f.desc));
          flagList.appendChild(item);
        });
        ticketOptsEl.appendChild(flagList);
      } else {
        ticketOptsEl.style.display = "none";
      }
    } else {
      ticketOptsEl.style.display = "none";
    }

    resultsEl.style.display = "block";
  }

  /**
   * Render the etype negotiation pipeline for v2 events.
   * Shows: Client Offer -> Account msDS-SET -> Service msDS-SET -> DC msDS-SET -> Result
   * Only displayed when v2 etype fields are present in the event.
   */
  function renderPipeline(parsed) {
    var pipelineEl = q("#evdec-pipeline");
    if (!pipelineEl) return;
    pipelineEl.innerHTML = "";

    var f = parsed.fields;
    /* Only show pipeline if we have at least the advertised etypes or SET fields */
    var hasV2 = f.ClientAdvertizedEncryptionTypes ||
                f.AccountSupportedEncryptionTypes ||
                f.ServiceSupportedEncryptionTypes;
    if (!hasV2) {
      pipelineEl.style.display = "none";
      return;
    }

    pipelineEl.style.display = "block";
    pipelineEl.appendChild(el("h3", "evdec-section-title", "Encryption Type Negotiation"));

    var pipe = el("div", "evdec-pipe");

    /* Build pipeline stages.  Each stage: label, value, source description. */
    var stages = [];

    if (f.ClientAdvertizedEncryptionTypes) {
      var etypes = f.ClientAdvertizedEncryptionTypes.split(/[\s,]+/).filter(function (s) { return s.length > 0; });
      stages.push({
        label: "Client Offer",
        value: etypes.join(", "),
        source: "Client machine GPO",
        cls: "evdec-pipe-stage--input"
      });
    }

    if (f.AccountSupportedEncryptionTypes && f.AccountSupportedEncryptionTypes !== "N/A") {
      stages.push({
        label: "Account msDS-SET",
        value: f.AccountSupportedEncryptionTypes,
        source: "AD attribute (Set-ADUser or GPO auto-update)",
        cls: "evdec-pipe-stage--input"
      });
    } else if (f.AccountSupportedEncryptionTypes === "N/A") {
      stages.push({
        label: "Account msDS-SET",
        value: "N/A (user account \u2014 uses DDSET fallback)",
        source: "DefaultDomainSupportedEncTypes on DC",
        cls: "evdec-pipe-stage--fallback"
      });
    }

    if (f.ServiceSupportedEncryptionTypes && f.ServiceSupportedEncryptionTypes !== "N/A") {
      stages.push({
        label: "Service msDS-SET",
        value: f.ServiceSupportedEncryptionTypes,
        source: "AD attribute on SPN target account",
        cls: "evdec-pipe-stage--input"
      });
    }

    if (f.DCSupportedEncryptionTypes && f.DCSupportedEncryptionTypes !== "N/A") {
      stages.push({
        label: "DC msDS-SET",
        value: f.DCSupportedEncryptionTypes,
        source: "DC computer account in AD (from DC GPO)",
        cls: "evdec-pipe-stage--input"
      });
    }

    /* Output stages: what the KDC actually selected */
    var outputs = [];
    if (f.TicketEncryptionType) {
      var te = decodeEncryptionType(f.TicketEncryptionType);
      outputs.push({ label: "Ticket Etype", value: te.name, security: te.security });
    }
    if (f.SessionKeyEncryptionType) {
      var se = decodeEncryptionType(f.SessionKeyEncryptionType);
      outputs.push({ label: "Session Key", value: se.name, security: se.security });
    }
    if (f.PreAuthEncryptionType) {
      var pe = decodeEncryptionType(f.PreAuthEncryptionType);
      outputs.push({ label: "Pre-Auth Etype", value: pe.name, security: pe.security });
    }

    /* Render input stages */
    stages.forEach(function (s, i) {
      if (i > 0) {
        pipe.appendChild(el("div", "evdec-pipe-arrow", "\u2193"));
      }
      var stage = el("div", "evdec-pipe-stage " + s.cls);
      stage.appendChild(el("div", "evdec-pipe-label", s.label));
      stage.appendChild(el("div", "evdec-pipe-value", s.value));
      stage.appendChild(el("div", "evdec-pipe-source", s.source));
      pipe.appendChild(stage);
    });

    /* Arrow to output */
    if (stages.length > 0 && outputs.length > 0) {
      var arrowBox = el("div", "evdec-pipe-arrow-result");
      arrowBox.appendChild(el("span", null, "\u2193"));
      arrowBox.appendChild(el("span", "evdec-pipe-arrow-label", " KDC negotiation "));
      arrowBox.appendChild(el("span", null, "\u2193"));
      pipe.appendChild(arrowBox);
    }

    /* Render output stages */
    if (outputs.length > 0) {
      var resultBox = el("div", "evdec-pipe-result");
      outputs.forEach(function (o) {
        var item = el("div", "evdec-pipe-result-item");
        item.appendChild(el("span", "evdec-pipe-result-label", o.label + ": "));
        item.appendChild(el("span", "evdec-pipe-result-value", o.value + " "));
        item.appendChild(el("span", "evdec-badge " + etypeBadgeClass(o.security), o.security));
        resultBox.appendChild(item);
      });
      pipe.appendChild(resultBox);
    }

    pipelineEl.appendChild(pipe);
  }

  /* ------------------------------------------------------------------ */
  /*  Copy Details — plain-text summary for troubleshooting              */
  /* ------------------------------------------------------------------ */

  /**
   * Build a plain-text summary of the decoded event with all etype
   * negotiation inputs and outputs.  Designed for pasting into tickets,
   * chat, or forum posts.
   */
  function buildCopyText(parsed) {
    var meta = EVENT_TYPES[parsed.eventId];
    var f = parsed.fields;
    var lines = [];

    /* Title line */
    var isSuccess = true;
    if (meta.alwaysFail) {
      isSuccess = false;
    } else if (meta.statusField && f[meta.statusField]) {
      isSuccess = parseHex(f[meta.statusField]) === 0;
    }
    lines.push("Kerberos Event " + parsed.eventId + " — " + meta.name + " — " + (isSuccess ? "Success" : "Failure"));

    /* Timestamp + DC */
    var metaParts = [];
    if (parsed.time) {
      metaParts.push(parsed.time.replace("T", " ").replace("Z", " UTC").replace(/\.(\d{3})\d*/, ".$1"));
    }
    if (parsed.computer) metaParts.push(parsed.computer);
    if (metaParts.length) lines.push(metaParts.join(" | "));
    lines.push("");

    /* Identity */
    if (f.TargetUserName) {
      var acct = f.TargetUserName;
      if (f.TargetDomainName) acct += " @ " + f.TargetDomainName;
      lines.push(pad("Account:", 18) + acct);
    }
    if (f.ServiceName) lines.push(pad("Service:", 18) + f.ServiceName);

    /* Status */
    if (f.Status) {
      var code = decodeResultCode(f.Status);
      var statusText = f.Status + " — " + code.name;
      if (code.desc) statusText += " — " + code.desc;
      lines.push(pad("Status:", 18) + statusText);
    }
    lines.push("");

    /* Etype negotiation inputs */
    var hasEtype = f.ClientAdvertizedEncryptionTypes ||
                   f.AccountSupportedEncryptionTypes ||
                   f.ServiceSupportedEncryptionTypes ||
                   f.DCSupportedEncryptionTypes;
    if (hasEtype) {
      lines.push("--- Encryption Type Negotiation ---");
      if (f.ClientAdvertizedEncryptionTypes) {
        var etypes = f.ClientAdvertizedEncryptionTypes.split(/[\s,]+/).filter(function (s) { return s.length > 0; });
        lines.push(pad("Client Offer:", 18) + etypes.join(", "));
      }
      if (f.AccountSupportedEncryptionTypes) {
        lines.push(pad("Account msDS-SET:", 18) + f.AccountSupportedEncryptionTypes);
      }
      if (f.AccountAvailableKeys) {
        lines.push(pad("Account Keys:", 18) + f.AccountAvailableKeys);
      }
      if (f.ServiceSupportedEncryptionTypes) {
        lines.push(pad("Service msDS-SET:", 18) + f.ServiceSupportedEncryptionTypes);
      }
      if (f.ServiceAvailableKeys) {
        lines.push(pad("Service Keys:", 18) + f.ServiceAvailableKeys);
      }
      if (f.DCSupportedEncryptionTypes) {
        lines.push(pad("DC msDS-SET:", 18) + f.DCSupportedEncryptionTypes);
      }
      if (f.DCAvailableKeys) {
        lines.push(pad("DC Keys:", 18) + f.DCAvailableKeys);
      }
      lines.push("");
    }

    /* KDC result etypes */
    var hasResult = f.TicketEncryptionType || f.SessionKeyEncryptionType || f.PreAuthEncryptionType;
    if (hasResult) {
      lines.push("--- KDC Result ---");
      if (f.TicketEncryptionType) {
        var te = decodeEncryptionType(f.TicketEncryptionType);
        lines.push(pad("Ticket Etype:", 18) + f.TicketEncryptionType + " " + te.name + " [" + te.security + "]");
      }
      if (f.SessionKeyEncryptionType) {
        var se = decodeEncryptionType(f.SessionKeyEncryptionType);
        lines.push(pad("Session Key:", 18) + f.SessionKeyEncryptionType + " " + se.name + " [" + se.security + "]");
      }
      if (f.PreAuthEncryptionType) {
        var pe = decodeEncryptionType(f.PreAuthEncryptionType);
        lines.push(pad("Pre-Auth Etype:", 18) + f.PreAuthEncryptionType + " " + pe.name + " [" + pe.security + "]");
      }
    }

    /* Pre-auth type */
    if (f.PreAuthType) {
      var pa = decodePreAuthType(f.PreAuthType);
      var paText = pa.name;
      if (pa.desc) paText += " — " + pa.desc;
      lines.push(pad("Pre-Auth Type:", 18) + paText);
    }
    if (hasResult || f.PreAuthType) lines.push("");

    /* Warnings */
    var warnings = generateWarnings(parsed);
    if (warnings.length > 0) {
      lines.push("--- Warnings ---");
      warnings.forEach(function (w) { lines.push("- " + w); });
    }

    return lines.join("\n");
  }

  /** Right-pad a label to a fixed width for monospace alignment. */
  function pad(label, width) {
    while (label.length < width) label += " ";
    return label;
  }

  /** Render the decoded meaning for a single field into the given TD element. */
  function renderDecodedValue(td, key, val, parsed) {
    if (!val || val === "-") {
      td.textContent = "-";
      return;
    }

    switch (key) {
      case "TicketOptions": {
        var flags = decodeTicketOptions(val);
        if (flags.length === 0) {
          td.textContent = "(none set)";
        } else {
          td.textContent = flags.map(function (f) { return f.name; }).join(", ");
        }
        break;
      }
      case "TicketEncryptionType":
      case "SessionKeyEncryptionType":
      case "PreAuthEncryptionType": {
        var etype = decodeEncryptionType(val);
        var span = el("span", null, etype.name + " ");
        var badge = el("span", "evdec-badge " + etypeBadgeClass(etype.security), etype.security);
        span.appendChild(badge);
        if (etype.note) {
          span.appendChild(document.createTextNode(" \u2014 " + etype.note));
        }
        td.appendChild(span);
        break;
      }
      case "Status": {
        var code = decodeResultCode(val);
        var text = code.name;
        if (code.desc) text += " \u2014 " + code.desc;
        td.appendChild(el("span", null, text));
        if (code.causes) {
          td.appendChild(el("div", "evdec-causes", code.causes));
        }
        break;
      }
      case "PreAuthType": {
        var pa = decodePreAuthType(val);
        td.textContent = pa.name + (pa.desc ? " \u2014 " + pa.desc : "");
        break;
      }
      case "IpAddress": {
        td.textContent = cleanIpAddress(val);
        break;
      }
      case "TargetSid":
      case "ServiceSid": {
        td.textContent = val;
        if (val === "S-1-0-0") {
          td.appendChild(el("span", "evdec-note", " (NULL SID \u2014 failure event)"));
        }
        break;
      }
      case "AccountSupportedEncryptionTypes":
      case "ServiceSupportedEncryptionTypes":
      case "DCSupportedEncryptionTypes": {
        /* These fields contain hex + text annotation, e.g. "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" */
        td.textContent = val;
        break;
      }
      case "ClientAdvertizedEncryptionTypes": {
        /* Space or newline separated etype names */
        var etypes = val.split(/[\s,]+/).filter(function (s) { return s.length > 0; });
        td.textContent = etypes.join(", ");
        break;
      }
      default:
        td.textContent = val;
    }
  }

  /* ------------------------------------------------------------------ */
  /*  URL hash — base64url-encoded XML for sharing                      */
  /* ------------------------------------------------------------------ */

  function toBase64Url(str) {
    try {
      var b64 = btoa(unescape(encodeURIComponent(str)));
      return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    } catch (_) { return ""; }
  }

  function fromBase64Url(b64url) {
    try {
      var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      return decodeURIComponent(escape(atob(b64)));
    } catch (_) { return ""; }
  }

  function pushHash(xmlStr) {
    try {
      var encoded = toBase64Url(xmlStr);
      if (encoded) {
        history.replaceState(null, "", "#xml=" + encoded);
      }
    } catch (_) { /* Swallow SecurityError in sandboxed iframes */ }
  }

  function clearHash() {
    try {
      history.replaceState(null, "", location.pathname);
    } catch (_) { }
  }

  /** Read XML from hash.  Returns the XML string, or empty string. */
  function readHash() {
    try {
      var h = location.hash.replace(/^#/, "");
      if (h.indexOf("xml=") === 0) {
        return fromBase64Url(h.substring(4));
      }
    } catch (_) { }
    return "";
  }

  /* ------------------------------------------------------------------ */
  /*  Clipboard                                                         */
  /* ------------------------------------------------------------------ */

  function copyText(text, btn) {
    if (!btn) return;
    var done = function () {
      var orig = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("evdec-btn--copied");
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove("evdec-btn--copied");
      }, 1200);
    };
    var fail = function () {
      var orig = btn.textContent;
      btn.textContent = "Failed";
      setTimeout(function () { btn.textContent = orig; }, 1500);
    };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(done).catch(fail);
    } else {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (ok) { done(); } else { fail(); }
      } catch (_) { fail(); }
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Event handlers                                                    */
  /* ------------------------------------------------------------------ */

  function onDecode() {
    var ta = q("#evdec-xml");
    var errorEl = q("#evdec-error");
    var resultsEl = q("#evdec-results");
    if (!ta) return;

    var raw = ta.value;
    if (!raw.trim()) {
      if (errorEl) { errorEl.textContent = "Paste an event XML into the text area above."; errorEl.style.display = "block"; }
      if (resultsEl) resultsEl.style.display = "none";
      return;
    }

    try {
      var parsed = parseEventXml(raw);
      if (errorEl) errorEl.style.display = "none";
      render(parsed);
      pushHash(raw.trim());
    } catch (msg) {
      if (errorEl) { errorEl.textContent = String(msg); errorEl.style.display = "block"; }
      if (resultsEl) resultsEl.style.display = "none";
      clearHash();
    }
  }

  function onClear() {
    var ta = q("#evdec-xml");
    var errorEl = q("#evdec-error");
    var resultsEl = q("#evdec-results");
    var actionsEl = q("#evdec-result-actions");
    if (ta) ta.value = "";
    if (errorEl) errorEl.style.display = "none";
    if (resultsEl) resultsEl.style.display = "none";
    if (actionsEl) actionsEl.style.display = "none";
    lastParsed = null;
    clearHash();
  }

  function onCopyLink(e) {
    copyText(location.href, e.currentTarget || e.target);
  }

  function onCopyDetails(e) {
    if (!lastParsed) return;
    copyText(buildCopyText(lastParsed), e.currentTarget || e.target);
  }

  function onExampleClick(e) {
    var btn = e.currentTarget || e.target;
    var key = btn.dataset.example;
    if (!key || !EXAMPLES[key]) return;
    var ta = q("#evdec-xml");
    if (ta) ta.value = EXAMPLES[key];
    onDecode();
  }

  /* ------------------------------------------------------------------ */
  /*  Safe event binding                                                */
  /* ------------------------------------------------------------------ */

  function on(sel, event, handler) {
    var elem = q(sel);
    if (elem) elem.addEventListener(event, handler);
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                              */
  /* ------------------------------------------------------------------ */

  function init() {
    try {
      root = document.getElementById("event-decoder");
      if (!root) return;

      if (root.dataset.evdecInit) return;
      root.dataset.evdecInit = "1";

      document.body.classList.add("event-decoder-page");

      on("#evdec-decode", "click", onDecode);
      on("#evdec-clear", "click", onClear);
      on("#evdec-copy-link", "click", onCopyLink);
      on("#evdec-copy-details", "click", onCopyDetails);

      qa(".evdec-example-btn").forEach(function (btn) {
        btn.addEventListener("click", onExampleClick);
      });

      /* Decode on Ctrl+Enter / Cmd+Enter in textarea */
      on("#evdec-xml", "keydown", function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
          e.preventDefault();
          onDecode();
        }
      });

      /* Read hash on load */
      var hashXml = readHash();
      if (hashXml) {
        var ta = q("#evdec-xml");
        if (ta) ta.value = hashXml;
        onDecode();
      }
    } catch (err) {
      if (typeof console !== "undefined" && console.error) {
        console.error("event-decoder init failed:", err);
      }
    }
  }

  /* Run after DOM is ready */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* mkdocs-material instant navigation re-triggers on page swap */
  if (typeof document$ !== "undefined") {
    document$.subscribe(function () {
      document.body.classList.remove("event-decoder-page");
      init();
    });
  }
})();
