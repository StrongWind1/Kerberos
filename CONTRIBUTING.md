# Contributing

## Getting started

```bash
git clone https://github.com/StrongWind1/Kerberos.git
cd Kerberos
uv sync --group docs
```

## Workflow

```bash
make serve   # live preview at http://127.0.0.1:8000
make docs    # full strict build (same as CI)
```

Or without Make:

```bash
uv run --group docs mkdocs serve
uv run --group docs mkdocs build --strict
```

## Content standards

**Accuracy first.** Every factual claim about protocol behavior should be traceable to a spec or a verified observation on a real DC. Inline citations use the format `[RFC 4120 §3.1]` or `[MS-KILE §3.3.5.7]`. If you are not certain something is correct, say so explicitly in the PR description.

**Vocabulary.** The site uses precise vocabulary for AD account types -- read [SPN-Bearing Account Types](https://strongwind1.github.io/Kerberos/security/msds-supported/#spn-bearing-account-types) before writing anything that touches account types or msDS-SupportedEncryptionTypes.

**PowerShell.** Every script in the security section should be tested against a real domain controller. State the DC OS version in the PR if the behavior is version-specific.

**Code block titles.** Add a `title="..."` to any code block that is 8+ lines or represents a complete standalone operation. Short snippets do not need titles.

**No AI attribution.** Do not mention AI tools in commits, PRs, or content.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes.
3. Run `make docs` and confirm the build passes with no warnings.
4. Open a PR against `main` using the PR template.

## Reporting errors

Use the [content error template](https://github.com/StrongWind1/Kerberos/issues/new?template=bug_report.md). Quote the incorrect text and provide the correct information with a spec reference if you have one.

## Scope

This site covers Kerberos authentication in Active Directory: protocol mechanics, security configuration, and attack techniques. Contributions outside this scope (e.g., LDAP internals, certificate services, general Windows hardening) will not be accepted unless they directly relate to a Kerberos attack or defense already covered.
