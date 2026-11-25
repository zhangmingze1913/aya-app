# Security Policy

## Scope

`aya-app` runs as root (or with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`) and
attaches eBPF programs to kernel hooks. A malformed policy can drop traffic,
break networking, or affect processes in a cgroup. Treat it as privileged
infrastructure tooling.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please use GitHub **Security Advisories** for this repository:

<https://github.com/zhangmingze1913/aya-app/security/advisories/new>

Do not file a public issue for:

- verifier bypasses;
- privilege escalation;
- kernel memory disclosure;
- denial of service caused by a program/policy.

Include the kernel version, architecture, command line, verifier log and a
minimal reproduction. Never include secrets or production packet captures.

## Operational guidance

- Test on a dedicated cgroup/interface, not the root cgroup or a production NIC.
- Keep programs attached only for the required lifetime.
- Review `docs/troubleshooting.md` before running `connect4`/LSM examples.
- QEMU TCG test timings are not production performance guarantees.
