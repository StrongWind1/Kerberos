# Group Policy Settings

Group Policy provides centralized management of Kerberos encryption types, ticket
lifetimes, and auditing across your domain.  These settings complement the
per-account `msDS-SupportedEncryptionTypes` attribute and per-DC registry keys.

---

## Encryption Types Policy

The primary GPO for controlling Kerberos encryption types.

### Policy Details

| Property | Value |
|---|---|
| **Policy name** | *Network security: Configure encryption types allowed for Kerberos* |
| **Path** | Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options |
| **Registry target** | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes` |

### Available Options

| Option | Effect When Checked |
|---|---|
| DES_CBC_CRC | Enables DES-CBC-CRC (etype 1) |
| DES_CBC_MD5 | Enables DES-CBC-MD5 (etype 3) |
| RC4_HMAC_MD5 | Enables RC4-HMAC (etype 23) |
| AES128_HMAC_SHA1 | Enables AES128-CTS-HMAC-SHA1-96 (etype 17) |
| AES256_HMAC_SHA1 | Enables AES256-CTS-HMAC-SHA1-96 (etype 18) |
| Future encryption types | Enables any future etypes added by Microsoft |

### Effect Depends on Where You Apply It

| Applied To | Effect |
|---|---|
| **Domain controllers** | Controls what the **KDC will accept and issue** for both AS and TGS exchanges.  This is the most impactful setting -- it acts as a hard filter on all ticket operations.  If RC4 is not checked here, the KDC will not issue RC4 tickets even if the target account allows RC4.  It also blocks pre-authentication with etypes not in the filter, which means new logon sessions will fail if the client only supports excluded etypes.  **Requires a KDC restart** (`Restart-Service kdc`) to take effect -- the KDC reads this value only at service start. |
| **Client workstations** | Controls what the **Kerberos client will request** in AS-REQ and TGS-REQ messages.  The client will not advertise etypes that are not enabled here. |
| **Member servers** | Controls what the **server's Kerberos client** will request, and updates the computer account's `msDS-SupportedEncryptionTypes` in AD. |

!!! tip "Recommended configuration for domain controllers"

    **AES-only DCs** (target state):

    ```
    Enabled:  AES128_HMAC_SHA1
              AES256_HMAC_SHA1
              Future encryption types
    Disabled: DES_CBC_CRC
              DES_CBC_MD5
              RC4_HMAC_MD5
    ```

    **AES+RC4 DCs** (transitional, while legacy accounts remain):

    ```
    Enabled:  RC4_HMAC_MD5
              AES128_HMAC_SHA1
              AES256_HMAC_SHA1
              Future encryption types
    Disabled: DES_CBC_CRC
              DES_CBC_MD5
    ```

!!! warning "Test before enforcing on DCs"
    Applying AES-only to domain controllers is a domain-wide change.  Any account that lacks
    AES keys or has `msDS-SupportedEncryptionTypes` set to RC4-only will immediately fail to
    authenticate.  Complete the [RC4 deprecation checklist](rc4-deprecation.md) before
    enabling this policy on DCs.

### Computer Accounts Auto-Update

When this policy is applied to a Windows machine, **two things happen**:

1. The GPO writes the `SupportedEncryptionTypes` registry value (the policy cache path).
2. The machine's Kerberos subsystem reads that registry value and **auto-updates its own
   computer account's** `msDS-SupportedEncryptionTypes` attribute in AD.

The AD attribute receives only the standard etype bits (0-4).  High bits like "Future
encryption types" (`0x40000000`) are present in the registry value but stripped from the AD
attribute.  For example, a GPO value of `0x7fffffff` produces an AD attribute of `0x1F` (31).

There may be a short delay between GPO application and the AD attribute update.  You do not
need to manually set `msDS-SupportedEncryptionTypes` on computer accounts that receive this
GPO.

This auto-update applies **only to the computer account** of the machine the GPO targets.
It does not affect user accounts, SPN-bearing accounts, or any other account in AD.  When applied
to a domain controller, the DC updates its own computer account (e.g., `DC01$`), not the
`krbtgt` account or any SPN-bearing account.

!!! warning "The GPO does NOT set `DefaultDomainSupportedEncTypes`"
    This GPO writes `SupportedEncryptionTypes` (the KDC etype filter), **not**
    `DefaultDomainSupportedEncTypes` (the fallback for unconfigured accounts).  These are
    different registry keys with different effects — and they operate independently.

    When both exist, `SupportedEncryptionTypes` overrides `DefaultDomainSupportedEncTypes`
    for ticket issuance.  The KDC does **not** intersect them: if the GPO filter allows only
    AES but DDSET says RC4, the KDC issues AES tickets (no error).  See
    [Registry Settings — Commonly Confused Keys](registry.md#commonly-confused-keys) for the
    full interaction model.

### Windows Server 2025 Security Baseline

The Microsoft security baseline for Server 2025 recommends disabling RC4.  The compliant
values for this policy are:

| Decimal | Meaning |
|---|---|
| 2147483624 | AES128 + Future encryption types |
| 2147483632 | AES256 + Future encryption types |
| 2147483640 | AES128 + AES256 + Future encryption types |

You can view compliance using Windows Admin Center (WAC) under the **Security Baseline** tab.

---

## Kerberos Ticket Lifetime Policies

These settings control how long Kerberos tickets remain valid.  They are configured in the
**Default Domain Policy** (or any GPO linked to the domain level).

### Policy Path

Computer Configuration > Policies > Windows Settings > Security Settings >
Account Policies > Kerberos Policy

### Settings

| Policy | Default | Meaning |
|---|---|---|
| **Maximum lifetime for user ticket** | 10 hours | How long a TGT is valid before the client must renew or obtain a new one. |
| **Maximum lifetime for service ticket** | 600 minutes (10 hours) | How long a service ticket is valid. |
| **Maximum lifetime for user ticket renewal** | 7 days | How long a TGT can be renewed without re-entering credentials. |
| **Maximum tolerance for computer clock synchronization** | 5 minutes | Maximum allowed clock skew between client and KDC.  Requests with timestamps outside this window are rejected (`KRB_AP_ERR_SKEW`). |
| **Enforce user logon restrictions** | Enabled | KDC validates user account restrictions (logon hours, disabled status) on every TGS request, not just at initial login. |

!!! info "Clock synchronization is critical"
    Kerberos relies on timestamps to prevent replay attacks.  If a client's clock drifts more
    than 5 minutes from the DC, all Kerberos operations will fail.  Ensure NTP is properly
    configured across your domain.  The default tolerance of 5 minutes should not be increased
    -- doing so weakens replay protection.

### Protected Users Group Override

Members of the **Protected Users** security group have a **4-hour non-renewable TGT
lifetime**, regardless of these policy settings.  This cannot be overridden by GPO.

---

## Kerberos Auditing Policies

Auditing is essential for detecting RC4 usage, failed authentication, and potential attacks
like Kerberoasting.  Without these policies enabled, your DCs will not generate the event IDs
you need for analysis.

### Policy Path

Computer Configuration > Policies > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Audit Policies > Account Logon

### Required Settings

| Subcategory | Recommended Setting | Event IDs Generated |
|---|---|---|
| **Audit Kerberos Authentication Service** | Success and Failure | **4768** (TGT request), **4771** (pre-auth failed) |
| **Audit Kerberos Service Ticket Operations** | Success and Failure | **4769** (service ticket request) |

Both subcategories should be set to **Success and Failure** on all domain controllers.

### Verifying Audit Configuration

You can check the current audit configuration directly on a DC:

--8<-- "includes/verify-kerberos-auditing.md"

Expected output:

```text title="Expected audit configuration output"
Kerberos Authentication Service      Success and Failure
Kerberos Service Ticket Operations   Success and Failure
```

### Enabling via GPO

1. Create or edit a GPO linked to the **Domain Controllers** OU.
2. Navigate to: Computer Configuration > Policies > Windows Settings > Security Settings >
   Advanced Audit Policy Configuration > Audit Policies > Account Logon.
3. Enable **Success** and **Failure** for both *Audit Kerberos Authentication Service* and
   *Audit Kerberos Service Ticket Operations*.
4. Run `gpupdate /force` on each DC or wait for the next policy refresh cycle.

!!! warning "Advanced Audit Policy vs. Basic Audit Policy"
    If you have never used Advanced Audit Policy Configuration before, you must also enable:

    Computer Configuration > Policies > Windows Settings > Security Settings > Local
    Policies > Security Options > **Audit: Force audit policy subcategory settings (Windows
    Vista or later) to override audit policy category settings**

    Set this to **Enabled**.  Without it, the basic audit policy settings may override your
    advanced audit configuration, and the detailed 4768/4769 events will not be generated.

### New Fields in 4768/4769 (January 2025+)

Starting with the January 2025 cumulative update, events 4768 and 4769 include additional
fields (`msDS-SupportedEncryptionTypes`, `Available Keys`, `Advertized Etypes`,
`Session Encryption Type`) that make it possible to identify RC4 dependencies from a single
event.  See [Troubleshooting — Event ID Reference](troubleshooting.md#event-id-reference) for
the full field descriptions.

---

## Other Relevant GPO Settings

### Account Lockout and Password Policies

While not Kerberos-specific, these affect Kerberos security indirectly:

| Policy | Path | Relevance |
|---|---|---|
| Minimum password length | Account Policies > Password Policy | Longer passwords resist Kerberoasting (25+ chars for user service accounts) |
| Account lockout threshold | Account Policies > Account Lockout Policy | Limits password spraying via AS-REQ |
| Account lockout duration | Account Policies > Account Lockout Policy | Balance between security and usability |

### Protected Users Group Behavior (GPO-Independent)

The **Protected Users** group enforces additional security restrictions (no NTLM, AES-only
pre-auth, 4-hour non-renewable TGT, no credential caching) that cannot be set via GPO.  See
[Mitigations — Protected Users](mitigations.md#priority-4-protected-users-group) for the full
details and guidance on which accounts to add.
