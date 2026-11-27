# Security Policy

## Supported Versions

Security fixes are applied to the latest minor release on `main`.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities in Siftsec (`siftsec`), including:
- Pickle / Torch / Safetensors parser bypasses or RCE/DoS vectors
- Secret redaction leaks in logs, SARIF, JSON, or Markdown reports
- Markdown / shell / HCL remediation injection vectors

Instead, report vulnerabilities privately via GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability**) with:
1. A minimal reproduction file or command
2. Affected version (`siftsec version`) and Python/OS environment
3. Potential impact

We aim to acknowledge reports within 48 hours and provide a patched release with regression/fuzz tests.
