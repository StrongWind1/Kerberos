# Ticket Forgery

Forging Kerberos tickets with stolen key material.

Ticket forgery attacks construct or modify Kerberos tickets outside of the KDC. With the right
key material, an attacker can create tickets that grant arbitrary identities and group memberships
-- effectively becoming any user in the domain. These are post-compromise persistence techniques:
the attacker has already obtained sensitive key material (typically the `krbtgt` hash or a service
account key) and uses ticket forgery to maintain access or escalate privileges.

The four forgery variants differ in what they forge, what key they require, and how detectable
the result is. Each represents a trade-off between simplicity and stealth.

---

## Attacks in This Category

| Attack | Forged Artifact | Key Required | Stealth Level | Description |
|--------|----------------|--------------|---------------|-------------|
| [Golden Ticket](golden-ticket.md) | TGT (from scratch) | `krbtgt` NT hash or AES key | Low -- detectable metadata anomalies, no Event 4768 | Forge a TGT with arbitrary PAC claims; the KDC trusts it because it decrypts with the real `krbtgt` key |
| [Silver Ticket](silver-ticket.md) | Service ticket (from scratch) | Target account NT hash or AES key | Moderate -- no DC logs, but PAC KDC signature is invalid | Forge a service ticket presented directly to the target service, bypassing the KDC entirely |
| [Diamond Ticket](diamond-ticket.md) | Modified legitimate TGT | `krbtgt` key | High -- legitimate ticket metadata, only PAC is modified | Request a real TGT, decrypt it with the `krbtgt` key, modify the PAC to add privileged groups, re-encrypt |
| [Sapphire Ticket](sapphire-ticket.md) | TGT with transplanted legitimate PAC | `krbtgt` key + controlled SPN-bearing account | Highest -- PAC contents match Active Directory exactly | Obtain a legitimate PAC for a high-privilege user via S4U2Self+U2U, transplant it into a TGT |

---

## Key Material Requirements

All forgery attacks require stolen key material. The most common sources:

| Key | How It Is Obtained | What It Enables |
|-----|--------------------|-----------------|
| `krbtgt` NT hash / AES key | DCSync, NTDS.dit extraction, DC compromise | Golden, Diamond, and Sapphire Tickets |
| User service account key | [Kerberoasting](../roasting/kerberoasting.md), LSASS dump, DCSync | Silver Tickets |
| Computer account key | LSASS dump on the target host, DCSync | Silver Tickets for services on that host |

!!! warning "If the attacker has the `krbtgt` key, the domain is fully compromised"
    Golden, Diamond, and Sapphire Tickets all require the `krbtgt` key. Obtaining this key
    means the attacker already has Domain Admin-equivalent access. These forgery techniques
    are used for **persistence and stealth**, not initial access. The primary defense is
    preventing `krbtgt` key compromise in the first place (restrict DCSync, tiered administration)
    and rotating the `krbtgt` password twice after any suspected compromise.

---

## Detection Difficulty Comparison

| Detection Method | Golden | Silver | Diamond | Sapphire |
|---|---|---|---|---|
| Missing Event 4768 (no AS Exchange) | Detectable | N/A | Not detectable (real AS Exchange) | Not detectable (real AS Exchange) |
| Anomalous ticket lifetime | Detectable | Detectable | Not detectable (real lifetime) | Not detectable (real lifetime) |
| PAC group mismatch with AD | Detectable | Detectable | Detectable | **Not detectable** (real PAC) |
| PAC KDC signature validation | Not effective (valid sig) | **Detectable** (invalid KDC sig) | Not effective (valid sig) | Not effective (valid sig) |
| Behavioral analytics | Possible | Possible | Required | Required |
