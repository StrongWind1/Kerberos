# Delegation Attacks

Abusing Kerberos delegation to impersonate users and escalate privileges.

Kerberos [delegation](../../protocol/delegation.md) allows a service to act on behalf of
authenticated users when accessing other services. All three delegation models -- unconstrained,
constrained, and resource-based constrained -- can be abused when an attacker compromises the
right account or has write access to the right AD object. These attacks leverage the
[S4U extensions](../../protocol/s4u.md) (S4U2Self and S4U2Proxy) to impersonate arbitrary
users, including Domain Admins, to target services.

Delegation abuse is one of the most common privilege escalation and lateral movement paths in
Active Directory environments.

---

## Attacks in This Category

| Attack | Delegation Type | Prerequisite | Description |
|--------|----------------|--------------|-------------|
| [Delegation Attacks](delegation-attacks.md) | Unconstrained, Constrained, RBCD | Varies (see below) | Comprehensive coverage of all three delegation abuse paths: TGT theft from unconstrained delegation hosts, S4U chains for constrained delegation, and RBCD abuse via writable computer objects |
| [S4U2Self Abuse](s4u2self-abuse.md) | S4U2Self (no delegation required) | Code execution as machine/virtual account | Local privilege escalation by requesting a service ticket as Domain Admin to the machine itself |
| [SPN-jacking](spn-jacking.md) | Constrained | Write access to `servicePrincipalName` attribute | Redirect constrained delegation to attacker-controlled accounts by moving the target SPN |

---

## Prerequisites by Attack Path

| Attack Path | What the Attacker Needs |
|---|---|
| **Unconstrained delegation abuse** | Compromise of a host with `TRUSTED_FOR_DELEGATION`; optionally, an authentication coercion technique (SpoolSample, PetitPotam) to force high-value targets to authenticate |
| **Constrained delegation abuse** | Compromise of an account with `msDS-AllowedToDelegateTo` configured |
| **RBCD abuse** | Write access to a target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute + control of a computer account (default `ms-DS-MachineAccountQuota` allows creating one) |
| **S4U2Self abuse** | Code execution as `NETWORK SERVICE`, a virtual account, or any context that authenticates as the computer account |
| **SPN-jacking** | Write access to the `servicePrincipalName` attribute on the target account (and on the original SPN owner for live SPN-jacking) |

---

## Protocol References

These attacks build on the delegation mechanisms and S4U sub-protocols documented in the
Protocol section:

- [Delegation](../../protocol/delegation.md) -- unconstrained, constrained, and RBCD mechanics
- [S4U Extensions](../../protocol/s4u.md) -- S4U2Self and S4U2Proxy protocol details,
  FORWARDABLE flag behavior, and authorization checks

---

## Common Defenses

- **Remove unnecessary unconstrained delegation** -- only domain controllers should have
  `TRUSTED_FOR_DELEGATION`
- **Protect high-value accounts** -- add to Protected Users group or set "Account is sensitive
  and cannot be delegated"
- **Set `ms-DS-MachineAccountQuota` to 0** -- prevent unprivileged users from creating machine
  accounts for RBCD abuse
- **Monitor attribute changes** -- Event 5136 for modifications to `msDS-AllowedToDelegateTo`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, and `servicePrincipalName`
- **Audit delegation configurations** regularly with PowerShell queries
