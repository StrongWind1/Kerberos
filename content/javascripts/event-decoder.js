/**
 * Kerberos Event Decoder — paste a Windows Security event (4768, 4769, 4770
 * or 4771) as XML or as the Event Viewer / Format-List text, and get field
 * explanations, KDC option flags, encryption type assessments and warnings.
 *
 * Plain browser script, no dependencies.  mkdocs.yml lists it under
 * extra_javascript, so it is loaded on every page; init() returns at once
 * when #event-decoder is not on the page.  Under Node (tests/js) the pure
 * functions are exported and no DOM is touched.
 */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /*  Event type metadata                                               */
  /* ------------------------------------------------------------------ */

  var EVENT_TYPES = {
    4768: { name: "TGT Request (AS-REQ)", desc: "A Kerberos authentication ticket (TGT) was requested.", hasStatus: true, statusLabel: "Result Code" },
    4769: { name: "Service Ticket Request (TGS-REQ)", desc: "A Kerberos service ticket was requested.", hasStatus: true, statusLabel: "Failure Code" },
    4770: { name: "Service Ticket Renewed", desc: "A Kerberos service ticket was renewed.", hasStatus: false, statusLabel: "Result Code" },
    4771: { name: "Pre-authentication Failed", desc: "Kerberos pre-authentication failed.", hasStatus: true, statusLabel: "Failure Code", alwaysFail: true }
  };

  /** Event IDs people paste that this tool deliberately does not decode. */
  var UNSUPPORTED_EVENT_NOTES = {
    4772: "Event 4772 (\"A Kerberos authentication ticket request failed\") is defined but Windows does not generate it; failed TGT requests are logged as 4768 or 4771.",
    4773: "Event 4773 (\"A Kerberos service ticket request failed\") is defined but Windows does not generate it; failed service ticket requests are logged as 4769."
  };

  /* ------------------------------------------------------------------ */
  /*  KDC options — the "Ticket Options" field of 4768/4769/4770/4771    */
  /*                                                                    */
  /*  The field is the kdc-options bit string of the request (RFC 4120  */
  /*  §5.4.1), not the flags of the issued ticket.  MSB 0 numbering:    */
  /*  bit 0 is 0x80000000; to test bit N use (value >>> (31 - N)) & 1.  */
  /*  Bit 14 is cname-in-addl-tkt [MS-SFU], bit 15 canonicalize (RFC    */
  /*  6806), bit 16 request-anonymous (RFC 8062).                       */
  /* ------------------------------------------------------------------ */

  var UNUSED_NOTE = "Not a KDC option (RFC 4120 §5.4.1). Event documentation labels this position with the ticket flag ";

  var KDC_OPTIONS = {
    0: { name: "reserved", desc: "Reserved." },
    1: { name: "forwardable", desc: "Client asks for a ticket that can be forwarded (used to obtain a TGT with different addresses)." },
    2: { name: "forwarded", desc: "This request is for a forwarded ticket (the TGT presented is forwardable)." },
    3: { name: "proxiable", desc: "Client asks for a ticket that can be used to obtain proxy tickets." },
    4: { name: "proxy", desc: "This request is for a proxy ticket with different network addresses." },
    5: { name: "allow-postdate", desc: "Client asks that postdated tickets may be issued from this one (not supported by KILE)." },
    6: { name: "postdated", desc: "Client asks for a postdated ticket (not supported by KILE)." },
    7: { name: "unused7", desc: UNUSED_NOTE + "\"Invalid\".", unused: true },
    8: { name: "renewable", desc: "Client asks for a renewable ticket." },
    9: { name: "unused9", desc: UNUSED_NOTE + "\"Initial\".", unused: true },
    10: { name: "unused10", desc: UNUSED_NOTE + "\"Pre-authent\".", unused: true },
    11: { name: "opt-hardware-auth", desc: "Hardware-authentication option (not used by Windows)." },
    12: { name: "unused12", desc: UNUSED_NOTE + "\"Transited-policy-checked\".", unused: true },
    13: { name: "unused13", desc: UNUSED_NOTE + "\"Ok-as-delegate\".", unused: true },
    14: { name: "cname-in-addl-tkt", desc: "S4U2Proxy (constrained delegation) request: the client name is taken from the additional ticket [MS-SFU]. Event documentation labels this bit \"Request-anonymous\"." },
    15: { name: "canonicalize", desc: "Client asks the KDC to canonicalize names and return referrals (RFC 6806). Set by Windows clients on almost every request." },
    16: { name: "request-anonymous", desc: "Anonymous ticket requested (RFC 8062; not used by KILE)." },
    26: { name: "disable-transited-check", desc: "Client asks the KDC not to check the transited field." },
    27: { name: "renewable-ok", desc: "A renewable ticket is acceptable if the requested lifetime cannot be granted." },
    28: { name: "enc-tkt-in-skey", desc: "Encrypt the ticket in the session key of the additional ticket (user-to-user)." },
    30: { name: "renew", desc: "This is a renewal request for an existing ticket." },
    31: { name: "validate", desc: "Request to validate a postdated ticket." }
  };

  /** Bit number of cname-in-addl-tkt, the S4U2Proxy marker. */
  var KDC_OPTION_S4U2PROXY = 14;

  /* ------------------------------------------------------------------ */
  /*  Encryption types — etype number to name and security assessment   */
  /* ------------------------------------------------------------------ */

  /* IANA Kerberos Encryption Type Numbers —
     https://www.iana.org/assignments/kerberos-parameters
     plus the negative Windows-internal RC4 variants.  Keys are unsigned
     32-bit values, so -128 is 0xFFFFFF80. */
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
    0x13: { name: "AES128-CTS-HMAC-SHA256-128", security: "strong", note: "RFC 8009; supported on Windows 11 24H2 / Server 2025, disabled by default (MS-KILE \u00a72.2.7); not lab-tested on this site" },
    0x14: { name: "AES256-CTS-HMAC-SHA384-192", security: "strong", note: "RFC 8009; supported on Windows 11 24H2 / Server 2025, disabled by default (MS-KILE \u00a72.2.7); not lab-tested on this site" },
    0x17: { name: "RC4-HMAC", security: "deprecated", note: "Deprecated (RFC 8429); not issued by default on DCs with the April 2026 cumulative update or later" },
    0x18: { name: "RC4-HMAC-EXP", security: "deprecated", note: "Deprecated (RFC 6649), export-grade" },
    0x19: { name: "CAMELLIA128-CTS-CMAC", security: "informational", note: "RFC 6803" },
    0x1A: { name: "CAMELLIA256-CTS-CMAC", security: "informational", note: "RFC 6803" },
    0x41: { name: "subkey-keymaterial", security: "informational", note: "Opaque (PacketCable)" },
    0xFFFFFF80: { name: "RC4-MD4", security: "deprecated", note: "Windows-internal etype -128" },
    0xFFFFFF7B: { name: "RC4-HMAC-OLD", security: "deprecated", note: "Windows-internal etype -133" },
    0xFFFFFF79: { name: "RC4-HMAC-OLD-EXP", security: "deprecated", note: "Windows-internal etype -135" },
    0xFFFFFFFF: { name: "(Failure)", security: "error", note: "No ticket was issued; shown in audit failure events" }
  };

  /* ------------------------------------------------------------------ */
  /*  Result / failure codes                                            */
  /*  RFC 4120 §7.5.9, RFC 4556 §3.1.3 (PKINIT), RFC 6113 §5.2 (FAST),  */
  /*  RFC 8636 (PKINIT algorithm agility).                              */
  /* ------------------------------------------------------------------ */

  var RESULT_CODES = {
    0x0: { name: "KDC_ERR_NONE", desc: "No error", causes: "" },
    0x1: { name: "KDC_ERR_NAME_EXP", desc: "Client's entry in KDC database has expired", causes: "" },
    0x2: { name: "KDC_ERR_SERVICE_EXP", desc: "Server's entry in KDC database has expired", causes: "" },
    0x3: { name: "KDC_ERR_BAD_PVNO", desc: "Requested Kerberos version number not supported", causes: "" },
    0x4: { name: "KDC_ERR_C_OLD_MAST_KVNO", desc: "Client's key encrypted in old master key", causes: "" },
    0x5: { name: "KDC_ERR_S_OLD_MAST_KVNO", desc: "Server's key encrypted in old master key", causes: "" },
    0x6: { name: "KDC_ERR_C_PRINCIPAL_UNKNOWN", desc: "Client not found in Kerberos database", causes: "The username doesn't exist." },
    0x7: { name: "KDC_ERR_S_PRINCIPAL_UNKNOWN", desc: "Server not found in Kerberos database", causes: "No account has the requested SPN registered." },
    0x8: { name: "KDC_ERR_PRINCIPAL_NOT_UNIQUE", desc: "Multiple principal entries in KDC database", causes: "Duplicate principal names exist. Check for duplicate SPNs." },
    0x9: { name: "KDC_ERR_NULL_KEY", desc: "Client or server has a null key", causes: "Reset the password on the account." },
    0xA: { name: "KDC_ERR_CANNOT_POSTDATE", desc: "Ticket not eligible for postdating", causes: "Client requested postdating, or time difference between client and KDC." },
    0xB: { name: "KDC_ERR_NEVER_VALID", desc: "Requested start time is later than end time", causes: "Time difference between KDC and client." },
    0xC: { name: "KDC_ERR_POLICY", desc: "KDC policy rejects request", causes: "Logon restrictions: workstation restriction, smart card requirement, or logon time restriction." },
    0xD: { name: "KDC_ERR_BADOPTION", desc: "KDC cannot accommodate requested option", causes: "TGT expiring, or a delegation request the KDC does not allow (for example an SPN not in the allowed-to-delegate-to list)." },
    0xE: { name: "KDC_ERR_ETYPE_NOSUPP", desc: "KDC has no support for encryption type", causes: "No etype is usable for this request: the client's etype list, the target account's effective set and keys, and the KDC filter have nothing in common." },
    0xF: { name: "KDC_ERR_SUMTYPE_NOSUPP", desc: "KDC has no support for checksum type", causes: "No key of the appropriate encryption type available." },
    0x10: { name: "KDC_ERR_PADATA_TYPE_NOSUPP", desc: "KDC has no support for PADATA type", causes: "Smart card certificate not found, or wrong CA. Check domain controller certificate." },
    0x11: { name: "KDC_ERR_TRTYPE_NOSUPP", desc: "KDC has no support for transited type", causes: "" },
    0x12: { name: "KDC_ERR_CLIENT_REVOKED", desc: "Client's credentials have been revoked", causes: "Account disabled, expired, or locked out." },
    0x13: { name: "KDC_ERR_SERVICE_REVOKED", desc: "Credentials for server have been revoked", causes: "" },
    0x14: { name: "KDC_ERR_TGT_REVOKED", desc: "TGT has been revoked", causes: "The KDC no longer accepts the TGT, for example because the account in it no longer matches (PAC requestor check). Get a new TGT." },
    0x15: { name: "KDC_ERR_CLIENT_NOTYET", desc: "Client not yet valid", causes: "" },
    0x16: { name: "KDC_ERR_SERVICE_NOTYET", desc: "Server not yet valid", causes: "" },
    0x17: { name: "KDC_ERR_KEY_EXPIRED", desc: "Password has expired", causes: "The user's password has expired." },
    0x18: { name: "KDC_ERR_PREAUTH_FAILED", desc: "Pre-authentication information was invalid", causes: "Wrong password provided." },
    0x19: { name: "KDC_ERR_PREAUTH_REQUIRED", desc: "Additional pre-authentication required", causes: "Normal first leg of an AS exchange for clients that do not send pre-authentication data up front." },
    0x1A: { name: "KDC_ERR_SERVER_NOMATCH", desc: "Requested server and ticket don't match", causes: "" },
    0x1B: { name: "KDC_ERR_MUST_USE_USER2USER", desc: "Server principal valid for user-to-user only", causes: "The target account has no SPN the KDC can issue a normal service ticket for; the client must use user-to-user authentication." },
    0x1C: { name: "KDC_ERR_PATH_NOT_ACCEPTED", desc: "KDC policy rejects transited path", causes: "" },
    0x1D: { name: "KDC_ERR_SVC_UNAVAILABLE", desc: "A service is not available", causes: "" },
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
    0x33: { name: "KRB_AP_PATH_NOT_ACCEPTED", desc: "Policy rejects transited path", causes: "" },
    0x34: { name: "KRB_ERR_RESPONSE_TOO_BIG", desc: "Response too big for UDP; retry with TCP", causes: "Ticket too large for UDP. The client retries with TCP." },
    0x3C: { name: "KRB_ERR_GENERIC", desc: "Generic error", causes: "Group membership overloaded PAC, recent password changes not propagated, SPN too long, or crypto subsystem error." },
    0x3D: { name: "KRB_ERR_FIELD_TOOLONG", desc: "Field is too long for this implementation", causes: "Request length exceeds 4-octet encoding limit." },
    0x3E: { name: "KDC_ERR_CLIENT_NOT_TRUSTED", desc: "PKINIT: the client's certificate is not trusted", causes: "Smart card certificate revoked or root CA not trusted by the DC." },
    0x3F: { name: "KDC_ERR_KDC_NOT_TRUSTED", desc: "PKINIT: the KDC's certificate could not be verified", causes: "The KDC has no certificate signed by a CA the client trusts." },
    0x40: { name: "KDC_ERR_INVALID_SIG", desc: "PKINIT: the signature is invalid", causes: "PKI trust exists but the client's signature on the AuthPack did not verify." },
    0x41: { name: "KDC_ERR_KEY_TOO_WEAK", desc: "PKINIT: Diffie-Hellman key parameters not accepted", causes: "Diffie-Hellman parameters too weak (KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED in RFC 4556)." },
    0x42: { name: "KDC_ERR_CERTIFICATE_MISMATCH", desc: "PKINIT: certificate mismatch", causes: "" },
    0x43: { name: "KRB_AP_ERR_NO_TGT", desc: "No TGT available to validate user-to-user", causes: "Service doesn't possess a TGT for user-to-user auth." },
    0x44: { name: "KDC_ERR_WRONG_REALM", desc: "Incorrect domain or principal", causes: "Cross-realm TGT presented to wrong realm. Check DNS configuration." },
    0x45: { name: "KRB_AP_ERR_USER_TO_USER_REQUIRED", desc: "Ticket must be for user-to-user", causes: "Service requires user-to-user authentication." },
    0x46: { name: "KDC_ERR_CANT_VERIFY_CERTIFICATE", desc: "PKINIT: the certificate cannot be verified", causes: "The certificate chain cannot be built to a trusted root." },
    0x47: { name: "KDC_ERR_INVALID_CERTIFICATE", desc: "PKINIT: the certificate is invalid", causes: "Certificate expired, or its signature does not verify." },
    0x48: { name: "KDC_ERR_REVOKED_CERTIFICATE", desc: "PKINIT: the certificate has been revoked", causes: "" },
    0x49: { name: "KDC_ERR_REVOCATION_STATUS_UNKNOWN", desc: "PKINIT: revocation status unknown", causes: "The CRL or OCSP responder did not give a definite answer." },
    0x4A: { name: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", desc: "PKINIT: revocation status unavailable", causes: "The CRL distribution point or OCSP responder could not be reached." },
    0x4B: { name: "KDC_ERR_CLIENT_NAME_MISMATCH", desc: "PKINIT: client name mismatch", causes: "The certificate does not map to the account named in the request." },
    0x4C: { name: "KDC_ERR_KDC_NAME_MISMATCH", desc: "PKINIT: KDC name mismatch", causes: "" },
    0x4D: { name: "KDC_ERR_INCONSISTENT_KEY_PURPOSE", desc: "PKINIT: the certificate cannot be used for this purpose", causes: "The certificate lacks the required extended key usage." },
    0x4E: { name: "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED", desc: "PKINIT: digest algorithm of the certificate not accepted", causes: "" },
    0x4F: { name: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED", desc: "PKINIT: paChecksum must be included", causes: "" },
    0x50: { name: "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED", desc: "PKINIT: digest algorithm of the signed data not accepted", causes: "" },
    0x51: { name: "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED", desc: "PKINIT: public key encryption not supported", causes: "" },
    0x5A: { name: "KDC_ERR_PREAUTH_EXPIRED", desc: "FAST: pre-authentication has expired", causes: "The client took too long; it restarts the exchange." },
    0x5B: { name: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED", desc: "FAST: more pre-authentication data is required", causes: "" },
    0x5C: { name: "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET", desc: "FAST: the authentication set is not acceptable", causes: "" },
    0x5D: { name: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS", desc: "FAST: unknown critical FAST options", causes: "" },
    0x64: { name: "KDC_ERR_NO_ACCEPTABLE_KDF", desc: "PKINIT: no acceptable key derivation function", causes: "" }
  };

  /* ------------------------------------------------------------------ */
  /*  Pre-authentication types                                          */
  /* ------------------------------------------------------------------ */

  var PREAUTH_TYPES = {
    0: { name: "(None)", desc: "No pre-authentication data" },
    2: { name: "PA-ENC-TIMESTAMP", desc: "Standard password authentication" },
    11: { name: "PA-ETYPE-INFO", desc: "KDC hints for encryption key selection" },
    14: { name: "PA-PK-AS-REQ_OLD", desc: "Smart card logon (pre-RFC PKINIT)" },
    15: { name: "PA-PK-AS-REP_OLD", desc: "Smart card logon (pre-RFC PKINIT)" },
    16: { name: "PA-PK-AS-REQ", desc: "Certificate or key-trust logon (PKINIT)" },
    17: { name: "PA-PK-AS-REP", desc: "Certificate or key-trust logon reply (PKINIT)" },
    19: { name: "PA-ETYPE-INFO2", desc: "KDC hints for encryption key selection (v2)" },
    20: { name: "PA-SVR-REFERRAL-INFO", desc: "KDC referral ticket" },
    129: { name: "PA-FOR-USER", desc: "S4U2Self request [MS-SFU]" },
    136: { name: "PA-FX-FAST", desc: "Kerberos armoring (FAST, RFC 6113)" },
    138: { name: "PA-ENCRYPTED-CHALLENGE", desc: "Kerberos armoring (FAST) encrypted challenge — Server 2012+" },
    165: { name: "PA-SUPPORTED-ENCTYPES", desc: "Supported encryption types [MS-KILE]" },
    167: { name: "PA-PAC-OPTIONS", desc: "PAC options [MS-KILE]" }
  };

  /* ------------------------------------------------------------------ */
  /*  SupportedEncryptionTypes bit names — [MS-KILE] §2.2.7             */
  /*  Must stay identical to BITS in etype-calculator.js (tests/js).    */
  /* ------------------------------------------------------------------ */

  var SET_BITS = [
    { bit: 0, name: "DES-CBC-CRC" },
    { bit: 1, name: "DES-CBC-MD5" },
    { bit: 2, name: "RC4-HMAC" },
    { bit: 3, name: "AES128-CTS-HMAC-SHA1-96" },
    { bit: 4, name: "AES256-CTS-HMAC-SHA1-96" },
    { bit: 5, name: "AES256-CTS-HMAC-SHA1-96-SK" },
    { bit: 6, name: "AES128-CTS-HMAC-SHA256-128" },
    { bit: 7, name: "AES256-CTS-HMAC-SHA384-192" },
    { bit: 16, name: "FAST-supported" },
    { bit: 17, name: "Compound-identity-supported" },
    { bit: 18, name: "Claims-supported" },
    { bit: 19, name: "Resource-SID-compression-disabled" }
  ];

  /** SupportedEncryptionTypes bit for an etype number, or 0 when it has none. */
  var ETYPE_TO_SET_BIT = { 0x1: 0x1, 0x3: 0x2, 0x17: 0x4, 0x11: 0x8, 0x12: 0x10, 0x13: 0x40, 0x14: 0x80 };

  /* ------------------------------------------------------------------ */
  /*  Human-readable field labels                                       */
  /* ------------------------------------------------------------------ */

  var FIELD_LABELS = {
    TargetUserName: "Account Name",
    TargetDomainName: "Account Domain",
    TargetSid: "Account SID",
    ServiceName: "Service Name",
    ServiceSid: "Service SID",
    TicketOptions: "Ticket Options (KDC options)",
    Status: "Result Code",
    TicketEncryptionType: "Ticket Encryption Type",
    PreAuthType: "Pre-Authentication Type",
    IpAddress: "Client Address",
    IpPort: "Client Port",
    CertIssuerName: "Certificate Issuer",
    CertSerialNumber: "Certificate Serial Number",
    CertThumbprint: "Certificate Thumbprint",
    LogonGuid: "Logon GUID",
    TransmittedServices: "Transited Services",
    ResponseTicket: "Response Ticket Hash",
    RequestTicketHash: "Request Ticket Hash",
    ResponseTicketHash: "Response Ticket Hash",
    AccountSupportedEncryptionTypes: "Account SupportedEncryptionTypes (effective)",
    AccountAvailableKeys: "Account Available Keys",
    ServiceSupportedEncryptionTypes: "Service SupportedEncryptionTypes (effective)",
    ServiceAvailableKeys: "Service Available Keys",
    DCSupportedEncryptionTypes: "DC SupportedEncryptionTypes",
    DCAvailableKeys: "DC Available Keys",
    ClientAdvertizedEncryptionTypes: "Client Advertised Etypes",
    SessionKeyEncryptionType: "Session Key Encryption Type",
    PreAuthEncryptionType: "Pre-Auth Encryption Type"
  };

  /* ------------------------------------------------------------------ */
  /*  Field source descriptions — where each value comes from.          */
  /* ------------------------------------------------------------------ */

  var EFFECTIVE_SET_RULE = "msDS-SupportedEncryptionTypes if non-zero, otherwise DefaultDomainSupportedEncTypes if set on the DC, otherwise the build default (0x27 before the April 2026 cumulative update, 0x18 on it or later)";

  /* The ticket and session key rules below are the TGS (service ticket)
     rules.  A TGT request (4768) follows the AS rules in
     FIELD_SOURCES_TGT; see security/etype-negotiation.md. */
  var TGT_TICKET_RULE = "A TGT is encrypted with one of the krbtgt account's keys, subject to the KDC filter.";
  var TGT_SESSION_RULE = "On a TGT request the session key is the strongest etype in the client's list that the KDC allows.";

  var FIELD_SOURCES = {
    TicketEncryptionType: "Chosen by the KDC: the strongest etype in the target account's effective set for which the account has keys, subject to the KDC filter. The client's etype list is not consulted unless KdcUseRequestedEtypesForTickets=1.",
    SessionKeyEncryptionType: "Needs an etype present in both the client's advertised list and the target account's effective set. The AES-SK bit (0x20) forces an AES session key when the set otherwise allows RC4. No overlap fails with KDC_ERR_ETYPE_NOSUPP.",
    PreAuthEncryptionType: "Etype of the key the client pre-authenticated with. Depends on the client's etype list and on which keys exist for the account in AD.",
    PreAuthType: "Pre-authentication method in the request. On a successful 4768, type 0 means the TGT was issued without pre-authentication: the account has \"Do not require Kerberos preauthentication\" set (UAC flag 0x400000). On a failure event the value says nothing about the account.",
    AccountSupportedEncryptionTypes: "The requesting account's set as the KDC evaluated it: " + EFFECTIVE_SET_RULE + ". Often N/A on a service ticket request; the requester's set is not an input to the service ticket's etype.",
    AccountAvailableKeys: "Key types stored in AD for this account. AES keys exist only if the password was set after the domain could generate them (domain functional level 2008 or later).",
    ServiceSupportedEncryptionTypes: "The target account's set as the KDC evaluated it, not necessarily the raw AD attribute: " + EFFECTIVE_SET_RULE + ".",
    ServiceAvailableKeys: "Key types stored in AD for the target account. The KDC can only issue a ticket etype the account has a key for.",
    DCSupportedEncryptionTypes: "The domain controller's own account value, shown for context. It is not an input to the etype chosen for other accounts' tickets. Microsoft describes it as a processed value: on Windows Server 2022 and earlier it always shows DES and RC4, regardless of the DC's settings. The KDC filter (the SupportedEncryptionTypes registry value on the DC) is not recorded in the event.",
    DCAvailableKeys: "Key types stored in AD for the DC's own account.",
    ClientAdvertizedEncryptionTypes: "Etype list the client sent in the request. On a Windows client it follows the machine's SupportedEncryptionTypes policy value (\"Configure encryption types allowed for Kerberos\").",
    Status: "Result code from the KDC. 0x0 = success. Non-zero codes say why the request was rejected.",
    TicketOptions: "The kdc-options the client set in the request (RFC 4120 §5.4.1). These are request options, not the flags of the issued ticket.",
    TransmittedServices: "The list of SPNs that were requested if constrained Kerberos delegation (S4U2Proxy) was used. \"-\" otherwise."
  };

  /** Field sources that differ on a TGT request (event 4768, the AS exchange). */
  var FIELD_SOURCES_TGT = {
    TicketEncryptionType: "Chosen by the KDC. " + TGT_TICKET_RULE,
    SessionKeyEncryptionType: TGT_SESSION_RULE
  };

  /** Where a field's value comes from, for the event it was logged in; undefined when there is no note. */
  function fieldSource(key, eventId) {
    return (eventId === 4768 ? lookup(FIELD_SOURCES_TGT, key) : undefined) || lookup(FIELD_SOURCES, key);
  }

  /* ------------------------------------------------------------------ */
  /*  Example events (sanitized from lab captures)                      */
  /* ------------------------------------------------------------------ */

  var EXAMPLES = {
    "4768-success": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4768</EventID><Version>2</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T07:46:35.1028890Z"/><EventRecordID>1620174</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="3292"/><Channel>Security</Channel><Computer>DC1.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">DC1$</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="TargetSid">S-1-5-21-1111111111-2222222222-3333333333-1000</Data><Data Name="ServiceName">krbtgt</Data><Data Name="ServiceSid">S-1-5-21-1111111111-2222222222-3333333333-502</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x0</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="PreAuthType">2</Data><Data Name="IpAddress">::1</Data><Data Name="IpPort">0</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data><Data Name="ResponseTicket">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=</Data><Data Name="AccountSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="AccountAvailableKeys">AES-SHA1, RC4</Data><Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data><Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="DCAvailableKeys">AES-SHA1, RC4</Data><Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 RC4-HMAC-NT RC4-HMAC-OLD RC4-MD4 RC4-HMAC-NT-EXP RC4-HMAC-OLD-EXP</Data><Data Name="SessionKeyEncryptionType">0x12</Data><Data Name="PreAuthEncryptionType">0x12</Data></EventData></Event>',

    "4769-success": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4769</EventID><Version>2</Version><Level>0</Level><Task>14337</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T07:58:08.1119718Z"/><EventRecordID>1620180</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="3440"/><Channel>Security</Channel><Computer>DC1.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">Administrator@CONTOSO.LOCAL</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="ServiceName">DC1$</Data><Data Name="ServiceSid">S-1-5-21-1111111111-2222222222-3333333333-1000</Data><Data Name="TicketOptions">0x40800000</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="IpAddress">::1</Data><Data Name="IpPort">0</Data><Data Name="Status">0x0</Data><Data Name="LogonGuid">{00000000-0000-4000-8000-000000000001}</Data><Data Name="TransmittedServices">-</Data><Data Name="RequestTicketHash">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=</Data><Data Name="ResponseTicketHash">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=</Data><Data Name="AccountSupportedEncryptionTypes">N/A</Data><Data Name="AccountAvailableKeys">N/A</Data><Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data><Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data><Data Name="DCAvailableKeys">AES-SHA1, RC4</Data><Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 RC4-HMAC-NT DES-CBC-MD5 DES-CBC-CRC RC4-HMAC-NT-EXP RC4-HMAC-OLD-EXP</Data><Data Name="SessionKeyEncryptionType">0x12</Data></EventData></Event>',

    "4771-failure": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4771</EventID><Version>0</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-04-07T06:00:54.0797513Z"/><EventRecordID>1619024</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1248"/><Channel>Security</Channel><Computer>DC1.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="TargetSid">S-1-5-21-1111111111-2222222222-3333333333-500</Data><Data Name="ServiceName">krbtgt/CONTOSO</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x18</Data><Data Name="PreAuthType">2</Data><Data Name="IpAddress">::ffff:192.0.2.100</Data><Data Name="IpPort">51032</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data></EventData></Event>',

    "4770-renew": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4770</EventID><Version>0</Version><Level>0</Level><Task>14337</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-04-07T03:26:23.4665529Z"/><EventRecordID>166481</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1084"/><Channel>Security</Channel><Computer>DC1.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">WS01$@CONTOSO.LOCAL</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="ServiceName">krbtgt</Data><Data Name="ServiceSid">S-1-5-21-1111111111-2222222222-3333333333-502</Data><Data Name="TicketOptions">0x2</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="IpAddress">::ffff:192.0.2.100</Data><Data Name="IpPort">49964</Data></EventData></Event>',

    "4768-failure": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4768</EventID><Version>0</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-04-07T08:15:42.3281200Z"/><EventRecordID>166750</EventRecordID><Correlation/><Execution ProcessID="712" ThreadID="1496"/><Channel>Security</Channel><Computer>DC1.contoso.local</Computer><Security/></System><EventData><Data Name="TargetUserName">nonexistent</Data><Data Name="TargetDomainName">CONTOSO.LOCAL</Data><Data Name="TargetSid">S-1-0-0</Data><Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data><Data Name="ServiceSid">S-1-0-0</Data><Data Name="TicketOptions">0x40810010</Data><Data Name="Status">0x6</Data><Data Name="TicketEncryptionType">0xffffffff</Data><Data Name="PreAuthType">0</Data><Data Name="IpAddress">::ffff:192.0.2.100</Data><Data Name="IpPort">49273</Data><Data Name="CertIssuerName"></Data><Data Name="CertSerialNumber"></Data><Data Name="CertThumbprint"></Data></EventData></Event>'
  };

  /* ------------------------------------------------------------------ */
  /*  Small helpers                                                     */
  /* ------------------------------------------------------------------ */

  /** Own-property lookup that is safe for keys such as "constructor". */
  function lookup(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
  }

  /** Throw an error whose message is meant for the user. */
  function fail(msg) {
    var e = new Error(msg);
    e.isDecodeError = true;
    throw e;
  }

  /** Field label, with the status field named the way the event itself names it. */
  function fieldLabel(key, eventId) {
    if (key === "Status") {
      var meta = lookup(EVENT_TYPES, eventId);
      return meta ? meta.statusLabel : "Result Code";
    }
    return lookup(FIELD_LABELS, key) || key;
  }

  /** Split a space/comma/newline separated etype list. */
  function splitEtypes(s) {
    return String(s || "").split(/[\s,]+/).filter(function (t) { return t.length > 0; });
  }

  /** True when a field holds a value, not the "-" or "N/A" the event shows when none was recorded. */
  function recorded(v) {
    return Boolean(v) && !/^(n\/a|-)$/i.test(String(v).trim());
  }

  /**
   * The etype names the client advertised.  Empty when the event recorded
   * none: "-" and "N/A" say nothing about the client.
   */
  function offeredEtypes(v) {
    return recorded(v) ? splitEtypes(v) : [];
  }

  /** "2026-04-07T07:46:35.1028890Z" -> "2026-04-07 07:46:35.102 UTC"; other formats pass through. */
  function formatTime(t) {
    if (!/^\d{4}-\d\d-\d\dT/.test(t || "")) return t || "";
    return t.replace("T", " ").replace(/\.(\d{3})\d*/, ".$1").replace(/Z$/, " UTC");
  }

  /* ------------------------------------------------------------------ */
  /*  Input parsing                                                     */
  /* ------------------------------------------------------------------ */

  /** Normalise line endings and strip a byte-order mark. */
  function cleanInput(raw) {
    return String(raw === null || raw === undefined ? "" : raw)
      .replace(/^﻿/, "")
      .replace(/\r\n?/g, "\n");
  }

  function unescapeEntities(s) {
    return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"")
      .replace(/&apos;|&#39;/g, "'").replace(/&amp;/g, "&");
  }

  /**
   * Find every <Event>…</Event> element in pasted text.
   * Tolerates anything before, between or after them: the text part of Event
   * Viewer's "Copy details as text" ("Event Xml:"), an <Events> wrapper from
   * a saved log, an XML declaration, the "- " node markers of the XML view,
   * and HTML-escaped markup.
   * Returns { events: [xml, …], incomplete } where incomplete is true when a
   * further <Event> starts after the last complete one but is cut off.
   * events is empty when there is no <Event> element.
   */
  function extractEventXmls(raw) {
    var s = cleanInput(raw);
    if (!/<Event[\s>]/.test(s) && /&lt;Event[\s&]/.test(s)) s = unescapeEntities(s);
    s = s.replace(/^[ \t]*-[ \t]+(?=<)/gm, "");

    var events = [];
    var incomplete = false;
    var re = /<Event[\s>]/g;
    var m;
    while ((m = re.exec(s)) !== null) {
      var close = s.indexOf("</Event>", m.index);
      if (close === -1) {
        if (events.length === 0) {
          fail("The XML is incomplete: there is no closing </Event> tag. Copy the whole event and try again.");
        }
        incomplete = true;
        break;
      }
      close += "</Event>".length;
      events.push(s.substring(m.index, close));
      re.lastIndex = close;
    }
    if (events.length === 0 && /<event[\s>]/i.test(s)) {
      fail("Found an <event> element, but Windows event XML uses <Event> and XML is case-sensitive. Paste the XML exactly as exported.");
    }
    return { events: events, incomplete: incomplete };
  }

  /** The first <Event>…</Event> element in pasted text, or null when there is none. */
  function extractEventXml(raw) {
    var found = extractEventXmls(raw).events;
    return found.length > 0 ? found[0] : null;
  }

  function checkEventId(idText) {
    var id = parseInt(idText, 10);
    if (lookup(EVENT_TYPES, id)) return id;
    var note = lookup(UNSUPPORTED_EVENT_NOTES, id);
    if (note) fail(note);
    fail("Unsupported event ID: " + (String(idText).trim() || "(none)") + ". This decoder handles Security-log events 4768, 4769, 4770 and 4771. KDC System-log events (Kdcsvc 201-209, KDC 14/16/26/27) are described on the Troubleshooting page.");
    return NaN;
  }

  /**
   * Parse event XML (already isolated by extractEventXml).
   * Returns { eventId, time, computer, fields, fieldOrder, format }.
   */
  function parseEventXml(xml) {
    /* Defensive validation for untrusted input before XML parsing. */
    if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) {
      fail("Invalid XML: DOCTYPE/ENTITY declarations are not allowed.");
    }

    var doc = new DOMParser().parseFromString(xml, "text/xml");
    var err = doc.getElementsByTagName("parsererror");
    if (err.length > 0) {
      fail("Invalid XML: " + (err[0].textContent || "parse error").replace(/\s+/g, " ").trim().substring(0, 200));
    }

    /* Element lookup that works with or without the event namespace. */
    function find(localName) {
      var els = doc.getElementsByTagName(localName);
      if (els.length === 0) els = doc.getElementsByTagNameNS("*", localName);
      return els;
    }
    function getText(localName) {
      var els = find(localName);
      return els.length > 0 ? (els[0].textContent || "") : "";
    }

    var eventId = checkEventId(getText("EventID"));
    var timeEls = find("TimeCreated");
    var time = timeEls.length > 0 ? (timeEls[0].getAttribute("SystemTime") || "") : "";

    var fields = {};
    var fieldOrder = [];
    var dataEls = find("Data");
    for (var i = 0; i < dataEls.length; i++) {
      var name = dataEls[i].getAttribute("Name");
      if (name && lookup(fields, name) === undefined) {
        fields[name] = (dataEls[i].textContent || "").trim();
        fieldOrder.push(name);
      }
    }

    return { eventId: eventId, time: time, computer: getText("Computer"), fields: fields, fieldOrder: fieldOrder, format: "xml" };
  }

  /* Labels of the text rendering (Event Viewer General tab, Get-WinEvent
     Message, "Copy details as text") mapped to the XML field names.  Keys are
     the label lower-cased with everything but letters and digits removed.
     A value of the form {account, service, dc} depends on the section. */
  var TEXT_FIELDS = {
    accountname: "TargetUserName",
    suppliedrealmname: "TargetDomainName",
    accountdomain: "TargetDomainName",
    userid: "TargetSid",
    securityid: "TargetSid",
    logonguid: "LogonGuid",
    servicename: "ServiceName",
    serviceid: "ServiceSid",
    clientaddress: "IpAddress",
    clientport: "IpPort",
    advertizedetypes: "ClientAdvertizedEncryptionTypes",
    advertisedetypes: "ClientAdvertizedEncryptionTypes",
    ticketoptions: "TicketOptions",
    resultcode: "Status",
    failurecode: "Status",
    ticketencryptiontype: "TicketEncryptionType",
    sessionencryptiontype: "SessionKeyEncryptionType",
    preauthenticationtype: "PreAuthType",
    preauthenticationencryptiontype: "PreAuthEncryptionType",
    transitedservices: "TransmittedServices",
    certificateissuername: "CertIssuerName",
    certificateserialnumber: "CertSerialNumber",
    certificatethumbprint: "CertThumbprint",
    requesttickethash: "RequestTicketHash",
    responsetickethash: "ResponseTicketHash",
    msdssupportedencryptiontypes: { account: "AccountSupportedEncryptionTypes", service: "ServiceSupportedEncryptionTypes", dc: "DCSupportedEncryptionTypes" },
    availablekeys: { account: "AccountAvailableKeys", service: "ServiceAvailableKeys", dc: "DCAvailableKeys" }
  };

  /** Fields that tell which section an abridged text paste is in. */
  var TEXT_SECTION_ANCHORS = {
    TargetUserName: "account", TargetDomainName: "account", TargetSid: "account", LogonGuid: "account",
    ServiceName: "service", ServiceSid: "service"
  };

  var TEXT_DESCRIPTIONS = [
    { re: /Kerberos authentication ticket \(TGT\) was requested/i, id: 4768 },
    { re: /Kerberos service ticket was requested/i, id: 4769 },
    { re: /Kerberos service ticket was renewed/i, id: 4770 },
    { re: /Kerberos pre-authentication failed/i, id: 4771 }
  ];

  /* Lines that occur once per event in every text rendering, keyed by the
     normalised label.  Seeing one of a kind a second time means the next
     event has started. */
  var TEXT_ONCE_PER_EVENT = {
    eventid: "id", id: "id",
    logname: "log",
    date: "time", timecreated: "time",
    computer: "computer", machinename: "computer"
  };

  /**
   * Split pasted text into one string per event.  A new event starts at a
   * wevtutil "Event[n]:" line, or at the second occurrence of a once-per-event
   * line: the description sentence, or the Event ID, Log Name, Date or
   * Computer line.  Text with a single event comes back as one piece.
   */
  function splitTextEvents(raw) {
    var chunks = [];
    var current = [];
    var seen = {};
    var anySeen = false;

    cleanInput(raw).split("\n").forEach(function (line) {
      var t = line.trim();
      var msg = /^Message\s*:\s*(.*)$/.exec(t);
      if (msg) t = msg[1].trim();

      var kind = null;
      var forced = /^Event\[\d+\]\s*:?$/.test(t);
      if (TEXT_DESCRIPTIONS.some(function (d) { return d.re.test(t); })) {
        kind = "description";
      } else {
        var kv = /^([^:]{1,60}?)\s*:/.exec(t);
        if (kv) kind = lookup(TEXT_ONCE_PER_EVENT, kv[1].toLowerCase().replace(/[^a-z0-9]/g, "")) || null;
      }

      if ((forced && anySeen) || (kind && seen[kind])) {
        chunks.push(current.join("\n"));
        current = [];
        seen = {};
        anySeen = false;
      }
      if (kind) { seen[kind] = true; anySeen = true; }
      current.push(line);
    });
    chunks.push(current.join("\n"));
    return chunks;
  }

  /**
   * Read the "Label: value" lines of one event's text rendering, optionally
   * under "Account Information:" style section headers.  Never fails:
   * returns whatever was recognised, as
   * { fields, fieldOrder, idText, time, computer, text }.
   */
  function scanEventText(raw) {
    var lines = cleanInput(raw).split("\n");
    var fields = {};
    var fieldOrder = [];
    var idText = "";
    var time = "";
    var computer = "";
    var section = "";
    var listField = null;

    lines.forEach(function (line) {
      var t = line.trim();
      if (!t) { listField = null; return; }

      /* Format-List puts the first description line after "Message :". */
      var msg = /^Message\s*:\s*(.*)$/.exec(t);
      if (msg) t = msg[1].trim();

      var sec = /^(Account|Service|Domain Controller|Network|Additional|Certificate|Ticket) information:?$/i.exec(t);
      if (sec) {
        var s = sec[1].toLowerCase();
        section = s === "domain controller" ? "dc" : s;
        listField = null;
        return;
      }

      var kv = /^([^:]{1,60}?)\s*:\s*(.*)$/.exec(t);
      if (!kv) {
        /* A bare etype name continues a multi-line "Advertized Etypes:" list. */
        if (listField && /^[A-Za-z0-9-]+$/.test(t)) {
          fields[listField] = (fields[listField] ? fields[listField] + " " : "") + t;
        }
        return;
      }
      listField = null;

      /* "UserId" is a property of the event record in Format-List * output
         (the Security log leaves it empty); the 4768 field is "User ID". */
      if (kv[1] === "UserId") return;

      var key = kv[1].toLowerCase().replace(/[^a-z0-9]/g, "");
      var val = kv[2].trim();

      if (key === "eventid" || key === "id") { if (!idText) idText = val; return; }
      if (key === "computer" || key === "machinename") { if (!computer) computer = val; return; }
      if (key === "date" || key === "timecreated") { if (!time) time = val; return; }

      var target = lookup(TEXT_FIELDS, key);
      if (target === undefined) return;
      if (typeof target !== "string") {
        target = lookup(target, section);
        if (target === undefined) return;
      }
      if (lookup(fields, target) === undefined) fieldOrder.push(target);
      fields[target] = val;
      if (target === "ClientAdvertizedEncryptionTypes") listField = target;
      var anchor = lookup(TEXT_SECTION_ANCHORS, target);
      if (anchor) section = anchor;
    });

    return { fields: fields, fieldOrder: fieldOrder, idText: idText, time: time, computer: computer, text: lines.join("\n") };
  }

  /**
   * Parse the text rendering of one event.  Accepts the Event Viewer General
   * tab, "Copy details as text", Format-List output and the abridged samples
   * used on this site.  Only the English labels are known.
   */
  function parseEventText(raw) {
    var scan = scanEventText(raw);
    var fields = scan.fields;
    var fieldOrder = scan.fieldOrder;
    var idText = scan.idText;
    var text = scan.text;

    if (fieldOrder.length < 2) {
      /* Event-shaped text whose labels are unknown: several "label: 0x…"
         lines, or the word Kerberos without one of the English description
         sentences.  That is what a non-English Windows produces. */
      var hexLines = (text.match(/:[ \t]*0x[0-9a-f]+[ \t]*$/gim) || []).length;
      var english = TEXT_DESCRIPTIONS.some(function (d) { return d.re.test(text); });
      if (hexLines >= 2 || (/kerberos/i.test(text) && !english)) {
        fail("The field labels in this text were not recognised. Only English-language event text is recognised. If the event comes from a Windows with another display language, paste the event XML instead (Event Viewer: Details tab, XML View, or right-click the event and Copy details as text, which includes the XML): the decoder reads the XML by field name, not by the translated labels.");
      }
      fail("This does not look like a Kerberos event. Paste the event XML (Event Viewer: Details tab, XML View, or right-click the event and Copy details as text), or the General tab text of event 4768, 4769, 4770 or 4771. Only English-language text is recognised; the XML is read by field name, whatever the display language.");
    }

    if (!idText) {
      var m = /\bEvent(?:\s*ID)?\s*[:#]?\s*(\d{4})\b/i.exec(text);
      if (m) idText = m[1];
      TEXT_DESCRIPTIONS.forEach(function (d) {
        if (!idText && d.re.test(text)) idText = String(d.id);
      });
    }
    if (!idText) {
      fail("Could not tell which event this is. Include the \"Event ID:\" line or the first sentence of the description (for example \"A Kerberos service ticket was requested.\"), or paste the XML view instead.");
    }

    return { eventId: checkEventId(idText), time: scan.time, computer: scan.computer, fields: fields, fieldOrder: fieldOrder, format: "text" };
  }

  /** Event ID of an isolated <Event> element without building a DOM, or "" when it has none. */
  function peekEventId(xml) {
    var m = /<EventID[^>]*>\s*(\d+)\s*<\/EventID>/.exec(xml);
    return m ? m[1] : "";
  }

  /**
   * Parse pasted input: XML when an <Event> element is present, text
   * otherwise.  One event is decoded at a time.  When the paste holds
   * several, the first one that decodes is returned and parsed.batch says so:
   * { count, index, incomplete } — events found, zero-based position of the
   * one returned, and whether a further XML event was cut off.
   */
  function parseEvent(raw) {
    var found = extractEventXmls(raw);
    var isXml = found.events.length > 0;
    var pieces = found.events;
    if (!isXml) {
      /* Only pieces with event fields count as events: a line of prose that
         happens to repeat a marker is not one.  With none, the whole text is
         parsed as before so that its error message describes all of it. */
      pieces = splitTextEvents(raw).filter(function (piece) { return scanEventText(piece).fieldOrder.length >= 2; });
      if (pieces.length === 0) pieces = [raw];
    }
    var parsed = null;
    var index = -1;
    var firstError = null;

    for (var i = 0; i < pieces.length && parsed === null; i++) {
      try {
        if (isXml) {
          /* An event of another ID is rejected from its ID alone, so a saved
             log with thousands of other events is not parsed one by one. */
          var id = peekEventId(pieces[i]);
          if (id && !lookup(EVENT_TYPES, parseInt(id, 10))) checkEventId(id);
          parsed = parseEventXml(pieces[i]);
        } else {
          parsed = parseEventText(pieces[i]);
        }
        index = i;
      } catch (e) {
        if (!e || !e.isDecodeError) throw e;
        if (firstError === null) firstError = e;
      }
    }

    var count = pieces.length + (found.incomplete ? 1 : 0);
    if (parsed === null) {
      if (count > 1) {
        fail("The pasted text holds " + count + " events and none of them could be decoded. The first one was rejected with: " + firstError.message);
      }
      throw firstError;
    }
    parsed.batch = { count: count, index: index, incomplete: found.incomplete };
    return parsed;
  }

  /**
   * Notices about the paste itself rather than about the event: shown above
   * the warnings and at the top of Copy Details.
   */
  function inputNotices(parsed) {
    var notes = [];
    var b = parsed.batch;
    if (b && b.count > 1) {
      notes.push("The pasted text holds " + b.count + " events" + (b.incomplete ? " (the last one is cut off)" : "")
        + ". Only one is decoded at a time: this is event " + (b.index + 1) + " of " + b.count
        + (b.index > 0 ? ", the first one that this decoder handles" : "")
        + ". Paste the others one at a time to decode them.");
    }
    return notes;
  }

  /* ------------------------------------------------------------------ */
  /*  Field decoders                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Parse a hex string (with or without 0x prefix) to an unsigned 32-bit
   * integer.  NaN when it is not hex or does not fit in 32 bits.
   */
  function parseHex(s) {
    s = String(s === null || s === undefined ? "" : s).trim().replace(/^0x/i, "");
    if (!s || !/^[0-9a-fA-F]+$/.test(s)) return NaN;
    if (s.replace(/^0+/, "").length > 8) return NaN;
    return parseInt(s, 16) >>> 0;
  }

  function hex(v) {
    return "0x" + (v >>> 0).toString(16).toUpperCase();
  }

  /**
   * Decode the Ticket Options hex string to the KDC options that are set.
   * Returns null when the value cannot be parsed, otherwise an array of
   * { bit, name, desc, unused } (empty when no bit is set).
   */
  function decodeKdcOptions(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return null;
    var flags = [];
    for (var bit = 0; bit < 32; bit++) {
      if (((val >>> (31 - bit)) & 1) !== 1) continue;
      var def = lookup(KDC_OPTIONS, bit);
      flags.push(def
        ? { bit: bit, name: def.name, desc: def.desc, unused: Boolean(def.unused) }
        : { bit: bit, name: "unassigned", desc: "Not assigned in RFC 4120 §5.4.1 or the Microsoft extensions.", unused: true });
    }
    return flags;
  }

  function hasKdcOption(hexStr, bit) {
    var val = parseHex(hexStr);
    return !isNaN(val) && ((val >>> (31 - bit)) & 1) === 1;
  }

  /** Decode encryption type hex to {name, security, note}. */
  function decodeEncryptionType(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return { name: (hexStr || "-") + " (unparseable)", security: "unknown", note: "" };
    return lookup(ENCRYPTION_TYPES, val) || { name: "Unknown (" + hex(val) + ")", security: "unknown", note: "" };
  }

  /** Decode result/status code hex to {name, desc, causes}. */
  function decodeResultCode(hexStr) {
    var val = parseHex(hexStr);
    if (isNaN(val)) return { name: (hexStr || "-") + " (unparseable)", desc: "", causes: "" };
    return lookup(RESULT_CODES, val) || { name: "Unknown error (" + hex(val) + ")", desc: "", causes: "" };
  }

  /** Decode pre-authentication type (decimal string) to {name, desc}. */
  function decodePreAuthType(decStr) {
    if (!/^\s*\d+\s*$/.test(decStr || "")) return { name: decStr || "-", desc: "" };
    var val = parseInt(decStr, 10);
    return lookup(PREAUTH_TYPES, val) || { name: "Unknown type (" + val + ")", desc: "" };
  }

  /** Clean IPv6-mapped IPv4 addresses for readability. */
  function cleanIpAddress(addr) {
    if (!addr) return "-";
    var match = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (match) return match[1] + " (IPv4-mapped)";
    if (addr === "::1") return "::1 (localhost)";
    return addr;
  }

  /**
   * Parse a *SupportedEncryptionTypes field such as
   * "0x27 (DES, RC4, AES-Sk)".  Returns null for N/A or text without a hex
   * value, otherwise { value, names } with the [MS-KILE] flag names.
   */
  function parseSetField(val) {
    var m = /^\s*(0x[0-9a-fA-F]+)/.exec(val || "");
    if (!m) return null;
    var v = parseHex(m[1]);
    if (isNaN(v)) return null;
    var names = [];
    var rest = v;
    SET_BITS.forEach(function (b) {
      var mask = (1 << b.bit) >>> 0;
      if (((v & mask) >>> 0) === mask) {
        names.push(b.name);
        rest = (rest & ~mask) >>> 0;
      }
    });
    if (rest !== 0) names.push(hex(rest) + " (undefined bits)");
    return { value: v, names: names };
  }

  /** True / false when an Available Keys field does / does not list AES; null when unknown. */
  function keysHaveAes(val) {
    if (!val || /^(n\/a|-)$/i.test(val.trim())) return null;
    return /AES/i.test(val);
  }

  /** "success", "failure", or "unknown" when the status field is missing or unreadable. */
  function eventOutcome(parsed) {
    var meta = lookup(EVENT_TYPES, parsed.eventId);
    if (meta.alwaysFail) return "failure";
    if (!meta.hasStatus) return "success";
    var status = parseHex(parsed.fields.Status);
    if (isNaN(status)) return "unknown";
    return status === 0 ? "success" : "failure";
  }

  /* ------------------------------------------------------------------ */
  /*  Security warnings engine                                          */
  /* ------------------------------------------------------------------ */

  var RC4_TODAY = "DCs with the April 2026 cumulative update or later no longer issue RC4 by default; it is used only where an account's msDS-SupportedEncryptionTypes or an explicit DefaultDomainSupportedEncTypes lists it.";

  function generateWarnings(parsed) {
    var w = [];
    var f = parsed.fields;
    var id = parsed.eventId;
    var ok = eventOutcome(parsed) === "success";
    /* 4768 and 4771 are logged for the AS exchange: the TGS rules for ticket
       and session key etypes (target account's effective set) do not
       describe it. */
    var isTgt = id === 4768 || id === 4771;

    var ticket = parseHex(f.TicketEncryptionType);
    var session = parseHex(f.SessionKeyEncryptionType);
    var preauth = parseHex(f.PreAuthEncryptionType);
    var isRc4 = function (v) { return v === 0x17 || v === 0x18; };
    var isDes = function (v) { return v === 0x1 || v === 0x3; };
    var isAes = function (v) { return v === 0x11 || v === 0x12 || v === 0x13 || v === 0x14; };

    [["TicketEncryptionType", ticket], ["SessionKeyEncryptionType", session], ["PreAuthEncryptionType", preauth]].forEach(function (pair) {
      if (isDes(pair[1])) {
        w.push("DES in " + fieldLabel(pair[0], id) + ". DES is removed in Windows Server 2025 and should not be in use.");
      }
    });
    if (isRc4(ticket)) {
      w.push(isTgt
        ? "The TGT is encrypted with RC4. " + TGT_TICKET_RULE
        : "The ticket is encrypted with RC4, so the target account's effective set lists RC4 (or the account has no AES keys). " + RC4_TODAY);
    }
    if (isRc4(session) && !isRc4(ticket)) {
      w.push(isTgt
        ? "The session key is RC4 although the ticket is not. " + TGT_SESSION_RULE
        : "The session key is RC4 although the ticket is not. The session key etype follows the client's etype list: this client offered no AES etype the target's effective set allows.");
    }
    if (isRc4(preauth)) {
      w.push("The client pre-authenticated with its RC4 key. Either the client offers only RC4, or the account has no AES keys (password not changed since the domain could generate them).");
    }

    /* Client etype list.  "-" and "N/A" mean the event recorded no list (as
       in Microsoft's own example of a 0xE failure), which says nothing about
       the client. */
    var offer = offeredEtypes(f.ClientAdvertizedEncryptionTypes);
    if (offer.length > 0 && !offer.some(function (e) { return /^AES/i.test(e); })) {
      w.push("The client offered no AES etype. On DCs with the April 2026 cumulative update or later a service ticket request from such a client is refused when the target account's effective set is AES-only; in this site's lab, earlier builds answered it with an RC4 session key.");
    }

    /* A TGT issued without pre-authentication.  PreAuthType is also 0 on
       failure events (unknown account, locked account), where it means nothing. */
    if (id === 4768 && ok && /^\s*0\s*$/.test(f.PreAuthType || "")) {
      w.push("A TGT was issued without pre-authentication (PreAuthType 0). The account has \"Do not require Kerberos preauthentication\" set, which makes it AS-REP roastable.");
    }

    /* S4U2Proxy.  A Transited Services value needs a letter or digit to
       count: "-" is the empty marker, and exports leave stray quotes around it. */
    var s4uOption = hasKdcOption(f.TicketOptions, KDC_OPTION_S4U2PROXY);
    var s4uTransited = recorded(f.TransmittedServices) && /[A-Za-z0-9]/.test(f.TransmittedServices);
    if (s4uOption || s4uTransited) {
      w.push((s4uOption
        ? "This is an S4U2Proxy (constrained delegation) request: KDC option cname-in-addl-tkt (bit 14) is set."
        : "Transited Services is populated, which indicates an S4U2Proxy (constrained delegation) request.")
        + (s4uTransited ? " Microsoft's event documentation describes Transited Services as the list of SPNs that were requested if constrained Kerberos delegation was used." : ""));
    }

    /* Specific failure code guidance */
    var status = parseHex(f.Status);
    if (status === 0x18) {
      w.push("Status 0x18 (KDC_ERR_PREAUTH_FAILED): wrong password. Many of these across accounts from one address suggests password spraying.");
    }
    if (status === 0x25) {
      w.push("Status 0x25 (KRB_AP_ERR_SKEW): clock skew exceeded tolerance. Make sure all machines sync time from the same source.");
    }
    if (status === 0xE) {
      /* The fields to compare differ between a TGT request and a service
         ticket request, and older or failed events do not carry them. */
      var etypeKeys = isTgt
        ? ["ClientAdvertizedEncryptionTypes", "AccountAvailableKeys", "ServiceAvailableKeys"]
        : ["ClientAdvertizedEncryptionTypes", "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys"];
      var etypeFields = isTgt
        ? "the client's advertised etypes and the Available Keys of the account and of krbtgt"
        : "the client's advertised etypes and the target account's SupportedEncryptionTypes and Available Keys";
      var advice;
      if (etypeKeys.some(function (k) { return recorded(f[k]); })) {
        advice = isTgt
          ? "Compare the client's advertised etypes with the Available Keys of the account and of krbtgt, then check"
          : "Compare the client's advertised etypes with the target account's effective SupportedEncryptionTypes and Available Keys, then check";
      } else {
        advice = (etypeKeys.some(function (k) { return lookup(f, k) !== undefined; })
          ? "This event shows \"-\" for " + etypeFields + ": the event gives no value for them."
          : (id === 4771
            ? "Event 4771 has no fields for " + etypeFields + "."
            : "This event has no fields for " + etypeFields + ". Windows Server 2016 and later log them once the January 14, 2025 or a later cumulative update is installed."))
          + (isTgt
            ? " Check the client's Kerberos etype policy, and whether the account's password was set after the domain could generate AES keys (domain functional level 2008 or later), then check"
            : " Read the target account's msDS-SupportedEncryptionTypes in Active Directory and the client's Kerberos etype policy instead, then check");
      }
      w.push("Status 0xE (KDC_ERR_ETYPE_NOSUPP): no usable etype. " + advice + " the KDC filter (SupportedEncryptionTypes registry value on the DC)."
        + (isTgt ? "" : " On DCs with the April 2026 cumulative update or later, an RC4-only client against an account with no msDS-SupportedEncryptionTypes fails here."));
    }
    if (status === 0x6) {
      w.push("Status 0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN): the account does not exist. Verify the username and domain.");
    }
    if (status === 0x12) {
      w.push("Status 0x12 (KDC_ERR_CLIENT_REVOKED): the account is disabled, expired, or locked out.");
    }

    /* Target account: effective set vs keys vs what was issued */
    var svcSet = parseSetField(f.ServiceSupportedEncryptionTypes);
    var svcAes = keysHaveAes(f.ServiceAvailableKeys);
    if (ok && !isTgt && isRc4(ticket) && isAes(session)) {
      w.push("AES-SK split: the session key is AES but the ticket is RC4. The AES-SK bit (0x20) in the target's effective set"
        + (svcSet ? " (" + hex(svcSet.value) + ")" : "")
        + " forced an AES session key; the ticket itself is still encrypted with the service account's RC4 key and can be cracked offline at RC4 speed (Kerberoasting).");
    }
    var ticketBit = lookup(ETYPE_TO_SET_BIT, ticket);
    if (ok && !isTgt && svcSet && ticketBit && (svcSet.value & 0xDF) !== 0 && (svcSet.value & ticketBit) === 0) {
      w.push("The ticket etype (" + decodeEncryptionType(f.TicketEncryptionType).name + ") is not in the target's effective SupportedEncryptionTypes (" + hex(svcSet.value) + "). Causes seen in this site's lab: KdcUseRequestedEtypesForTickets=1 on the DC; a KDC filter that excludes every etype in the set on a DC without the April 2026 cumulative update; or, on Server 2022 build 20348.5020, an AES-only KDC filter that upgraded the RC4 fallback of an account with no msDS-SupportedEncryptionTypes to an AES256 ticket.");
    }
    if (svcSet && (svcSet.value & 0x18) !== 0 && svcAes === false) {
      w.push("The target's effective set allows AES (" + hex(svcSet.value) + ") but the account has no AES keys (Available Keys: " + f.ServiceAvailableKeys.trim() + "). Reset the account's password to generate them. Until then the KDC can only issue RC4 where RC4 is allowed; otherwise the request fails with KDC_ERR_ETYPE_NOSUPP.");
    }
    var acctSet = parseSetField(f.AccountSupportedEncryptionTypes);
    if (id === 4768 && acctSet && (acctSet.value & 0x18) !== 0 && keysHaveAes(f.AccountAvailableKeys) === false) {
      w.push("The account's effective set allows AES (" + hex(acctSet.value) + ") but it has no AES keys (Available Keys: " + f.AccountAvailableKeys.trim() + "). Reset its password to generate them.");
    }

    /* A service ticket's target account whose effective set has legacy
       etypes only.  The requester's set (Account, on 4768) and the DC's own
       set are not inputs to the ticket etype, and 0x27 was the default for
       every unset account before the April 2026 cumulative update, so those
       are not flagged. */
    if (!isTgt && svcSet && (svcSet.value & 0x7) !== 0 && (svcSet.value & 0x18) === 0) {
      w.push(fieldLabel("ServiceSupportedEncryptionTypes", id) + " lists no AES etype (" + hex(svcSet.value) + "). Tickets for this account use RC4 or DES, and requests fail with KDC_ERR_ETYPE_NOSUPP when the client does not allow them. Under an AES-only KDC filter this site's lab (Server 2022 build 20348.5020) saw KDC_ERR_ETYPE_NOSUPP when the set was the account's own msDS-SupportedEncryptionTypes, and an AES256 ticket when it was the DC's fallback for an account with no attribute.");
    }

    return w;
  }

  /* ------------------------------------------------------------------ */
  /*  Etype selection summary                                           */
  /* ------------------------------------------------------------------ */

  /**
   * Describe how the KDC arrived at each etype in the event, as data:
   * [{ title, rule, stages: [{label, value, source, kind}], result }].
   * The ticket etype and the session key etype have different inputs, so
   * they are separate groups.  Empty when the event has none of the fields.
   */
  function buildPipeline(parsed) {
    var f = parsed.fields;
    var groups = [];
    /* 4768 is the AS exchange.  Its ticket (the TGT) and session key are not
       chosen from the target account's effective set, so that stage and the
       TGS rules are left out. */
    var isTgt = parsed.eventId === 4768;
    var present = recorded;
    var result = function (label, raw) {
      var e = decodeEncryptionType(raw);
      return { label: label, value: e.name, security: e.security };
    };
    var offer = offeredEtypes(f.ClientAdvertizedEncryptionTypes).join(", ");
    var targetSet = !isTgt && present(f.ServiceSupportedEncryptionTypes)
      ? { label: "Target account effective set", value: f.ServiceSupportedEncryptionTypes, source: "msDS-SupportedEncryptionTypes if non-zero, otherwise DefaultDomainSupportedEncTypes, otherwise the build default", kind: "input" }
      : null;
    var filter = { label: "KDC filter", value: "Not recorded in the event", source: "SupportedEncryptionTypes registry value on the DC; applied when the KDC starts", kind: "fallback" };

    if (f.TicketEncryptionType && (present(f.ServiceSupportedEncryptionTypes) || present(f.ServiceAvailableKeys))) {
      var stages = [];
      if (targetSet) stages.push(targetSet);
      if (present(f.ServiceAvailableKeys)) {
        stages.push({
          label: "Target account keys",
          value: f.ServiceAvailableKeys,
          source: isTgt ? "Key types stored in AD for the account named in Service Name (krbtgt on a TGT request)" : "Key types stored in AD for the account",
          kind: "input"
        });
      }
      stages.push(filter);
      groups.push({
        title: "Ticket encryption",
        rule: isTgt
          ? TGT_TICKET_RULE
          : "Strongest etype in the set that the account has a key for and the filter allows. The client's list is not consulted unless KdcUseRequestedEtypesForTickets=1.",
        stages: stages,
        result: result("Ticket etype", f.TicketEncryptionType)
      });
    }

    if (f.SessionKeyEncryptionType && (offer || targetSet)) {
      var sStages = [];
      if (offer) sStages.push({ label: "Client offer", value: offer, source: "Etype list sent in the request", kind: "input" });
      if (targetSet) sStages.push(targetSet);
      if (isTgt) sStages.push(filter);
      groups.push({
        title: "Session key",
        rule: isTgt
          ? TGT_SESSION_RULE
          : "Needs an etype present in both. The AES-SK bit (0x20) forces an AES session key when the set otherwise allows RC4. No overlap fails with KDC_ERR_ETYPE_NOSUPP.",
        stages: sStages,
        result: result("Session key", f.SessionKeyEncryptionType)
      });
    }

    if (f.PreAuthEncryptionType && (offer || present(f.AccountAvailableKeys))) {
      var pStages = [];
      if (offer) pStages.push({ label: "Client offer", value: offer, source: "Etype list sent in the request", kind: "input" });
      if (present(f.AccountAvailableKeys)) {
        pStages.push({ label: "Account keys", value: f.AccountAvailableKeys, source: "Key types stored in AD for the requesting account", kind: "input" });
      }
      groups.push({
        title: "Pre-authentication",
        rule: "The key the client proved it knows: an etype the client offers and the account has a key for.",
        stages: pStages,
        result: result("Pre-auth etype", f.PreAuthEncryptionType)
      });
    }

    return groups;
  }

  /* ------------------------------------------------------------------ */
  /*  Copy Details — plain-text summary for troubleshooting              */
  /* ------------------------------------------------------------------ */

  /** Right-pad a label to a fixed width for monospace alignment. */
  function pad(label, width) {
    while (label.length < width) label += " ";
    return label;
  }

  var OUTCOME_TEXT = { success: "Success", failure: "Failure", unknown: "Status missing" };

  /**
   * Build a plain-text summary of the decoded event with every input to the
   * etype decision.  Designed for pasting into tickets, chat, or forum posts.
   */
  function buildCopyText(parsed) {
    var meta = lookup(EVENT_TYPES, parsed.eventId);
    var f = parsed.fields;
    var lines = [];
    var row = function (label, value) { lines.push(pad(label, 20) + value); };

    lines.push("Kerberos Event " + parsed.eventId + " — " + meta.name + " — " + OUTCOME_TEXT[eventOutcome(parsed)]);
    var metaParts = [];
    if (parsed.time) metaParts.push(formatTime(parsed.time));
    if (parsed.computer) metaParts.push(parsed.computer);
    if (metaParts.length) lines.push(metaParts.join(" | "));
    inputNotices(parsed).forEach(function (text) { lines.push("Note: " + text); });
    lines.push("");

    if (f.TargetUserName) row("Account:", f.TargetUserName + (f.TargetDomainName ? " @ " + f.TargetDomainName : ""));
    if (f.ServiceName) row("Service:", f.ServiceName);
    if (f.Status) {
      var code = decodeResultCode(f.Status);
      row(meta.statusLabel + ":", f.Status + " — " + code.name + (code.desc ? " — " + code.desc : ""));
    }
    if (f.TicketOptions) {
      var opts = decodeKdcOptions(f.TicketOptions);
      row("KDC options:", f.TicketOptions + " — " + (opts === null ? "unparseable" : (opts.map(function (o) { return o.name; }).join(", ") || "none set")));
    }
    lines.push("");

    var inputs = [
      ["Client offer:", f.ClientAdvertizedEncryptionTypes],
      ["Account set:", f.AccountSupportedEncryptionTypes],
      ["Account keys:", f.AccountAvailableKeys],
      ["Service set:", f.ServiceSupportedEncryptionTypes],
      ["Service keys:", f.ServiceAvailableKeys],
      ["DC set:", f.DCSupportedEncryptionTypes],
      ["DC keys:", f.DCAvailableKeys]
    ].filter(function (p) { return Boolean(p[1]); });
    if (inputs.length) {
      lines.push("--- Etype inputs (sets are effective values; the KDC filter is not in the event) ---");
      inputs.forEach(function (p, i) {
        /* "-" and "N/A" are the event's markers for a value it did not record. */
        if (!recorded(p[1])) {
          row(p[0], "not recorded (" + p[1].trim() + ")");
        } else {
          row(p[0], i === 0 ? splitEtypes(p[1]).join(", ") : p[1]);
        }
      });
      lines.push("");
    }

    var outputs = [
      ["Ticket etype:", f.TicketEncryptionType],
      ["Session key:", f.SessionKeyEncryptionType],
      ["Pre-auth etype:", f.PreAuthEncryptionType]
    ].filter(function (p) { return Boolean(p[1]); });
    if (outputs.length) {
      lines.push("--- KDC result ---");
      outputs.forEach(function (p) {
        var e = decodeEncryptionType(p[1]);
        row(p[0], p[1] + " " + e.name + " [" + e.security + "]");
      });
    }
    if (f.PreAuthType) {
      var pa = decodePreAuthType(f.PreAuthType);
      row("Pre-auth type:", pa.name + (pa.desc ? " — " + pa.desc : ""));
    }
    if (outputs.length || f.PreAuthType) lines.push("");

    var warnings = generateWarnings(parsed);
    if (warnings.length > 0) {
      lines.push("--- Warnings ---");
      warnings.forEach(function (text) { lines.push("- " + text); });
    }

    return lines.join("\n").replace(/\n+$/, "");
  }

  /* ------------------------------------------------------------------ */
  /*  Share link — base64url-encoded input in the URL hash               */
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

  /** "#xml=<base64url>" for an event, or "" when there is nothing to share. */
  function buildShareHash(raw) {
    var encoded = toBase64Url(String(raw || "").trim());
    return encoded ? "#xml=" + encoded : "";
  }

  /** Event text carried by a "#xml=…" hash, or "". */
  function readShareHash(hash) {
    var h = String(hash || "").replace(/^#/, "");
    return h.indexOf("xml=") === 0 ? fromBase64Url(h.substring(4)) : "";
  }

  /* ------------------------------------------------------------------ */
  /*  Browser-only code below                                           */
  /* ------------------------------------------------------------------ */

  var root = null;
  /** Last decoded event, for the Copy Details button. */
  var lastParsed = null;

  function q(sel) { return root ? root.querySelector(sel) : null; }
  function qa(sel) { return root ? Array.prototype.slice.call(root.querySelectorAll(sel)) : []; }

  function on(sel, event, handler) {
    var elem = q(sel);
    if (elem) elem.addEventListener(event, handler);
  }

  /** Create a DOM element with optional class and text content. */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /** Map etype security level to badge CSS class. */
  function etypeBadgeClass(security) {
    switch (security) {
      case "removed": return "evdec-badge--removed";
      case "deprecated": return "evdec-badge--deprecated";
      case "recommended":
      case "strong": return "evdec-badge--recommended";
      case "error": return "evdec-badge--error";
      default: return "evdec-badge--neutral";
    }
  }

  function renderHeader(headerEl, parsed) {
    clear(headerEl);
    var meta = lookup(EVENT_TYPES, parsed.eventId);
    var outcome = eventOutcome(parsed);

    var headerRow = el("div", "evdec-header-row");
    headerRow.appendChild(el("span", "evdec-event-badge", String(parsed.eventId)));
    var titleWrap = el("div", "evdec-header-title");
    titleWrap.appendChild(el("span", "evdec-event-name", meta.name));
    titleWrap.appendChild(el("span", "evdec-event-desc", meta.desc));
    headerRow.appendChild(titleWrap);
    headerRow.appendChild(el("span", "evdec-status evdec-status--" + outcome, OUTCOME_TEXT[outcome]));
    headerEl.appendChild(headerRow);

    if (parsed.time || parsed.computer || parsed.format === "text") {
      var metaLine = el("div", "evdec-header-meta");
      if (parsed.time) metaLine.appendChild(el("span", "evdec-meta-item", formatTime(parsed.time)));
      if (parsed.computer) metaLine.appendChild(el("span", "evdec-meta-item", parsed.computer));
      if (parsed.format === "text") metaLine.appendChild(el("span", "evdec-meta-item", "parsed from text; paste the XML view for every field"));
      headerEl.appendChild(metaLine);
    }
  }

  function renderPipeline(pipelineEl, parsed) {
    clear(pipelineEl);
    var groups = buildPipeline(parsed);
    if (groups.length === 0) {
      pipelineEl.style.display = "none";
      return;
    }
    pipelineEl.style.display = "block";
    pipelineEl.appendChild(el("h2", "evdec-section-title", "How the KDC Chose These Etypes"));

    var wrap = el("div", "evdec-pipe-groups");
    groups.forEach(function (g) {
      var pipe = el("div", "evdec-pipe");
      pipe.appendChild(el("div", "evdec-pipe-title", g.title));
      g.stages.forEach(function (s) {
        var stage = el("div", "evdec-pipe-stage evdec-pipe-stage--" + s.kind);
        stage.appendChild(el("div", "evdec-pipe-label", s.label));
        stage.appendChild(el("div", "evdec-pipe-value", s.value));
        stage.appendChild(el("div", "evdec-pipe-source", s.source));
        pipe.appendChild(stage);
        pipe.appendChild(el("div", "evdec-pipe-arrow", "↓"));
      });
      var resultBox = el("div", "evdec-pipe-result");
      var item = el("div", "evdec-pipe-result-item");
      item.appendChild(el("span", "evdec-pipe-result-label", g.result.label + ": "));
      item.appendChild(el("span", "evdec-pipe-result-value", g.result.value + " "));
      item.appendChild(el("span", "evdec-badge " + etypeBadgeClass(g.result.security), g.result.security));
      resultBox.appendChild(item);
      resultBox.appendChild(el("div", "evdec-pipe-rule", g.rule));
      pipe.appendChild(resultBox);
      wrap.appendChild(pipe);
    });
    pipelineEl.appendChild(wrap);
  }

  /** Render the decoded meaning for a single field into the given TD element. */
  function renderDecodedValue(td, key, val) {
    if (!val || val === "-") {
      td.textContent = "-";
      return;
    }

    switch (key) {
      case "TicketOptions": {
        var flags = decodeKdcOptions(val);
        if (flags === null) {
          td.textContent = "Unparseable (expected a hex value such as 0x40810010)";
        } else {
          td.textContent = flags.map(function (o) { return o.name; }).join(", ") || "(none set)";
        }
        break;
      }
      case "TicketEncryptionType":
      case "SessionKeyEncryptionType":
      case "PreAuthEncryptionType": {
        var etype = decodeEncryptionType(val);
        var span = el("span", null, etype.name + " ");
        span.appendChild(el("span", "evdec-badge " + etypeBadgeClass(etype.security), etype.security));
        if (etype.note) span.appendChild(document.createTextNode(" — " + etype.note));
        td.appendChild(span);
        break;
      }
      case "Status": {
        var code = decodeResultCode(val);
        td.appendChild(el("span", null, code.name + (code.desc ? " — " + code.desc : "")));
        if (code.causes) td.appendChild(el("div", "evdec-causes", code.causes));
        break;
      }
      case "PreAuthType": {
        var pa = decodePreAuthType(val);
        td.textContent = pa.name + (pa.desc ? " — " + pa.desc : "");
        break;
      }
      case "IpAddress":
        td.textContent = cleanIpAddress(val);
        break;
      case "TargetSid":
      case "ServiceSid":
        td.textContent = val;
        if (val === "S-1-0-0") td.appendChild(el("span", "evdec-note", " (NULL SID — failure event)"));
        break;
      case "AccountSupportedEncryptionTypes":
      case "ServiceSupportedEncryptionTypes":
      case "DCSupportedEncryptionTypes": {
        /* Hex plus the event's own annotation, e.g. "0x27 (DES, RC4, AES-Sk)". */
        var set = parseSetField(val);
        td.textContent = set ? set.names.join(", ") || "(no bits set)" : val;
        break;
      }
      case "ClientAdvertizedEncryptionTypes":
        td.textContent = splitEtypes(val).join(", ");
        break;
      default:
        td.textContent = val;
    }
  }

  function renderFields(fieldsEl, parsed) {
    clear(fieldsEl);
    /* Explicit table roles throughout: on a phone extra.css lays each field
       out as a block (display: block on the table, its rows and cells), and
       some browsers have dropped table semantics when display changes.  The
       roles say what the elements already are, so nothing depends on that. */
    var table = el("table", "evdec-table");
    table.setAttribute("role", "table");
    table.appendChild(el("caption", "evdec-sr-only", "Decoded fields of event " + parsed.eventId));
    var thead = el("thead");
    thead.setAttribute("role", "rowgroup");
    var headRow = el("tr");
    headRow.setAttribute("role", "row");
    ["Field", "Raw Value", "Decoded"].forEach(function (h) {
      var th = el("th", null, h);
      th.setAttribute("scope", "col");
      th.setAttribute("role", "columnheader");
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el("tbody");
    tbody.setAttribute("role", "rowgroup");
    parsed.fieldOrder.forEach(function (key) {
      var val = parsed.fields[key];
      var tr = el("tr");
      tr.setAttribute("role", "row");
      var th = el("th", "evdec-field-name", fieldLabel(key, parsed.eventId));
      th.setAttribute("scope", "row");
      th.setAttribute("role", "rowheader");
      tr.appendChild(th);

      var rawTd = el("td", "evdec-field-raw");
      rawTd.setAttribute("role", "cell");
      rawTd.appendChild(el("code", null, val || "-"));
      tr.appendChild(rawTd);

      var decodedTd = el("td", "evdec-field-decoded");
      decodedTd.setAttribute("role", "cell");
      renderDecodedValue(decodedTd, key, val);
      var source = fieldSource(key, parsed.eventId);
      if (source) decodedTd.appendChild(el("div", "evdec-field-source", source));
      tr.appendChild(decodedTd);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    fieldsEl.appendChild(table);
  }

  function renderKdcOptions(optsEl, parsed) {
    clear(optsEl);
    var flags = parsed.fields.TicketOptions ? decodeKdcOptions(parsed.fields.TicketOptions) : null;
    if (!flags || flags.length === 0) {
      optsEl.style.display = "none";
      return;
    }
    optsEl.style.display = "block";
    optsEl.appendChild(el("h2", "evdec-section-title", "KDC Options Breakdown"));
    var flagList = el("div", "evdec-flag-list");
    flags.forEach(function (o) {
      var item = el("div", "evdec-flag-item" + (o.unused ? " evdec-flag-item--unused" : ""));
      item.appendChild(el("span", "evdec-flag-bit", "Bit " + o.bit));
      item.appendChild(el("span", "evdec-flag-name", o.name));
      item.appendChild(el("span", "evdec-flag-desc", o.desc));
      flagList.appendChild(item);
    });
    optsEl.appendChild(flagList);
  }

  function render(parsed) {
    lastParsed = parsed;
    var resultsEl = q("#evdec-results");
    var headerEl = q("#evdec-header");
    var warningsEl = q("#evdec-warnings");
    var fieldsEl = q("#evdec-fields");
    var optsEl = q("#evdec-ticket-options");
    var pipelineEl = q("#evdec-pipeline");
    var actionsEl = q("#evdec-result-actions");
    if (!resultsEl || !headerEl || !warningsEl || !fieldsEl || !optsEl) return;

    if (actionsEl) actionsEl.style.display = "flex";
    renderHeader(headerEl, parsed);

    /* Notices about the paste (several events, one decoded) come first. */
    var warnings = inputNotices(parsed).concat(generateWarnings(parsed));
    clear(warningsEl);
    warnings.forEach(function (msg) {
      warningsEl.appendChild(el("div", "evdec-warning-item", msg));
    });
    warningsEl.style.display = warnings.length ? "block" : "none";

    if (pipelineEl) renderPipeline(pipelineEl, parsed);
    renderFields(fieldsEl, parsed);
    renderKdcOptions(optsEl, parsed);

    resultsEl.style.display = "block";
  }

  /* ------------------------------------------------------------------ */
  /*  Clipboard                                                         */
  /* ------------------------------------------------------------------ */

  function copyText(text, btn) {
    if (!btn) return;
    var flash = function (label, cls, ms) {
      var orig = btn.dataset.label || btn.textContent;
      btn.dataset.label = orig;
      btn.textContent = label;
      btn.classList.add(cls);
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove(cls);
      }, ms);
    };
    var done = function () { flash("Copied", "evdec-btn--copied", 1200); };
    var failed = function () { flash("Failed", "evdec-btn--failed", 1500); };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(done).catch(failed);
      return;
    }
    /* Fallback: temporary textarea + execCommand */
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) { done(); } else { failed(); }
    } catch (_) {
      failed();
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Event handlers                                                    */
  /* ------------------------------------------------------------------ */

  function showError(msg) {
    var errorEl = q("#evdec-error");
    var resultsEl = q("#evdec-results");
    if (errorEl) { errorEl.textContent = msg; errorEl.style.display = "block"; }
    if (resultsEl) resultsEl.style.display = "none";
    lastParsed = null;
  }

  /**
   * Decode the textarea.  The pasted event is never written to the address
   * bar: events carry account names, SIDs and client addresses, and a URL
   * ends up in browser history.  Sharing is explicit, via Copy Link.
   */
  function decode(moveFocus) {
    var ta = q("#evdec-xml");
    if (!ta) return;
    if (!ta.value.trim()) {
      showError("Paste an event into the text area above.");
      return;
    }
    try {
      var parsed = parseEvent(ta.value);
      var errorEl = q("#evdec-error");
      if (errorEl) errorEl.style.display = "none";
      render(parsed);
      var resultsEl = q("#evdec-results");
      if (moveFocus && resultsEl) resultsEl.focus();
    } catch (err) {
      showError(err && err.isDecodeError ? err.message : "Unexpected error while decoding: " + (err && err.message ? err.message : String(err)));
    }
  }

  function onClear() {
    var ta = q("#evdec-xml");
    var errorEl = q("#evdec-error");
    var resultsEl = q("#evdec-results");
    var actionsEl = q("#evdec-result-actions");
    if (ta) { ta.value = ""; ta.focus(); }
    if (errorEl) errorEl.style.display = "none";
    if (resultsEl) resultsEl.style.display = "none";
    if (actionsEl) actionsEl.style.display = "none";
    lastParsed = null;
    /* Drop a shared event from the address bar, keeping path and query. */
    try {
      if (location.hash.indexOf("#xml=") === 0) {
        history.replaceState(history.state, "", location.pathname + location.search);
      }
    } catch (_) { /* SecurityError in sandboxed iframes */ }
  }

  function onCopyLink(e) {
    var ta = q("#evdec-xml");
    var hash = buildShareHash(ta ? ta.value : "");
    if (!hash) {
      /* Nothing pasted: a "Copied" confirmation for a link with no event in
         it would mislead.  A result already on screen is left alone. */
      var errorEl = q("#evdec-error");
      if (errorEl) {
        errorEl.textContent = "Nothing to share yet. Paste an event into the text area above, then press Copy Link.";
        errorEl.style.display = "block";
      }
      return;
    }
    copyText(location.origin + location.pathname + hash, e.currentTarget);
  }

  function onCopyDetails(e) {
    if (lastParsed) copyText(buildCopyText(lastParsed), e.currentTarget);
  }

  function onExampleClick(e) {
    var example = lookup(EXAMPLES, e.currentTarget.dataset.example);
    if (!example) return;
    var ta = q("#evdec-xml");
    if (ta) ta.value = example;
    decode(true);
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                              */
  /* ------------------------------------------------------------------ */

  var BODY_CLASS = "event-decoder-page";

  function init() {
    try {
      root = document.getElementById("event-decoder");
      /* The body class is a fallback for browsers without :has(); it must
         not survive an instant navigation to another page. */
      document.body.classList.toggle(BODY_CLASS, Boolean(root));
      if (!root) return;

      /* Prevent duplicate listeners when instant navigation re-runs init. */
      if (root.dataset.evdecInit) return;
      root.dataset.evdecInit = "1";
      lastParsed = null;

      on("#evdec-decode", "click", function () { decode(true); });
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
          decode(true);
        }
      });

      /* A shared link carries the event in the hash. */
      var shared = "";
      try { shared = readShareHash(location.hash); } catch (_) { /* location inaccessible */ }
      if (shared) {
        var ta = q("#evdec-xml");
        if (ta) ta.value = shared;
        decode(false);
      }
    } catch (err) {
      if (typeof console !== "undefined" && console.error) {
        console.error("event-decoder init failed:", err);
      }
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      EVENT_TYPES: EVENT_TYPES,
      KDC_OPTIONS: KDC_OPTIONS,
      ENCRYPTION_TYPES: ENCRYPTION_TYPES,
      RESULT_CODES: RESULT_CODES,
      PREAUTH_TYPES: PREAUTH_TYPES,
      SET_BITS: SET_BITS,
      FIELD_LABELS: FIELD_LABELS,
      FIELD_SOURCES: FIELD_SOURCES,
      FIELD_SOURCES_TGT: FIELD_SOURCES_TGT,
      EXAMPLES: EXAMPLES,
      fieldLabel: fieldLabel,
      fieldSource: fieldSource,
      extractEventXml: extractEventXml,
      extractEventXmls: extractEventXmls,
      parseEventXml: parseEventXml,
      splitTextEvents: splitTextEvents,
      parseEventText: parseEventText,
      parseEvent: parseEvent,
      inputNotices: inputNotices,
      parseHex: parseHex,
      decodeKdcOptions: decodeKdcOptions,
      decodeEncryptionType: decodeEncryptionType,
      decodeResultCode: decodeResultCode,
      decodePreAuthType: decodePreAuthType,
      cleanIpAddress: cleanIpAddress,
      parseSetField: parseSetField,
      eventOutcome: eventOutcome,
      generateWarnings: generateWarnings,
      buildPipeline: buildPipeline,
      buildCopyText: buildCopyText,
      buildShareHash: buildShareHash,
      readShareHash: readShareHash
    };
  }

  if (typeof document === "undefined") return;

  /* Run after DOM is ready — covers the first page load. */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Material's instant navigation swaps the page body without reloading
     scripts; document$ emits after every swap. */
  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  }
})();
