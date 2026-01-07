# FastSMTP Code Review Tasks

Issues identified during the senior developer code review conducted on 2026-01-07.

All issues have been created in the GitHub issue tracker:
https://github.com/jsenecal/fastsmtp/issues

## Summary by Priority

| Priority | Label | Count | Description |
|----------|-------|-------|-------------|
| P0 | `P0: critical` | 3 | Data loss or security vulnerability |
| P1 | `P1: high` | 4 | Significant bugs or security concerns |
| P2 | `P2: medium` | 11 | Edge cases and performance issues |
| P3 | `P3: low` | 13 | Code quality and minor improvements |
| **Total** | | **31** | |

## Issue Index

### P0: Critical

| Issue | Title |
|-------|-------|
| [#1](https://github.com/jsenecal/fastsmtp/issues/1) | Message Queue Data Loss Risk |
| [#2](https://github.com/jsenecal/fastsmtp/issues/2) | Incomplete Message Processing Pipeline |
| [#3](https://github.com/jsenecal/fastsmtp/issues/3) | HTTP Client State Leak on Worker Restart |

### P1: High (Security)

| Issue | Title |
|-------|-------|
| [#4](https://github.com/jsenecal/fastsmtp/issues/4) | DNS Rebinding Attack Vector (TOCTOU) |
| [#5](https://github.com/jsenecal/fastsmtp/issues/5) | Regex Timeout Silently Bypasses Rules |
| [#6](https://github.com/jsenecal/fastsmtp/issues/6) | API Key Prefix Collision and Timing Attack |
| [#7](https://github.com/jsenecal/fastsmtp/issues/7) | No Rate Limiting on SMTP Server |

### P2: Medium (Edge Cases)

| Issue | Title |
|-------|-------|
| [#8](https://github.com/jsenecal/fastsmtp/issues/8) | Soft Delete Not Applied in SMTP Lookups |
| [#9](https://github.com/jsenecal/fastsmtp/issues/9) | Unicode/IDN Domain Handling Missing |
| [#10](https://github.com/jsenecal/fastsmtp/issues/10) | Weak Message-ID Fallback Generation |
| [#11](https://github.com/jsenecal/fastsmtp/issues/11) | Multiple NULL Catch-All Recipients Possible |
| [#12](https://github.com/jsenecal/fastsmtp/issues/12) | Multiple Recipients per Email Not Handled |
| [#13](https://github.com/jsenecal/fastsmtp/issues/13) | Attachment Content Not Included in Webhook |

### P2: Medium (Performance)

| Issue | Title |
|-------|-------|
| [#14](https://github.com/jsenecal/fastsmtp/issues/14) | N+1 Query in Webhook Worker |
| [#15](https://github.com/jsenecal/fastsmtp/issues/15) | Unbounded Memory in Rules Evaluation |
| [#16](https://github.com/jsenecal/fastsmtp/issues/16) | Fixed Thread Pool Size for Regex |
| [#17](https://github.com/jsenecal/fastsmtp/issues/17) | Blocking DNS Resolution in Async Context |
| [#18](https://github.com/jsenecal/fastsmtp/issues/18) | Cleanup Worker May Not Keep Up With Large Logs |

### P3: Low (Code Quality)

| Issue | Title |
|-------|-------|
| [#19](https://github.com/jsenecal/fastsmtp/issues/19) | Global State in Multiple Modules |
| [#20](https://github.com/jsenecal/fastsmtp/issues/20) | Inconsistent Error Handling in CLI |
| [#21](https://github.com/jsenecal/fastsmtp/issues/21) | Missing Input Validation on Rules |
| [#22](https://github.com/jsenecal/fastsmtp/issues/22) | onupdate Does Not Trigger on Direct SQL Updates |

### P3: Low (Architecture)

| Issue | Title |
|-------|-------|
| [#23](https://github.com/jsenecal/fastsmtp/issues/23) | Implement Dead Letter Queue |
| [#24](https://github.com/jsenecal/fastsmtp/issues/24) | Expand Health Check Depth |
| [#25](https://github.com/jsenecal/fastsmtp/issues/25) | Add Backpressure on Delivery Queue |
| [#26](https://github.com/jsenecal/fastsmtp/issues/26) | Add Idempotency Key for Webhooks |
| [#27](https://github.com/jsenecal/fastsmtp/issues/27) | Graceful Degradation When Database is Down |

### P3: Low (Minor)

| Issue | Title |
|-------|-------|
| [#28](https://github.com/jsenecal/fastsmtp/issues/28) | Duration Parsing Misleading Behavior |
| [#29](https://github.com/jsenecal/fastsmtp/issues/29) | Root User Hardcoded UUID Conflict Risk |
| [#30](https://github.com/jsenecal/fastsmtp/issues/30) | No Maximum Webhook Payload Size |
| [#31](https://github.com/jsenecal/fastsmtp/issues/31) | TLS Certificate Hot-Reload Not Supported |

## Filtering Issues

Use GitHub labels to filter issues:

- [P0: Critical](https://github.com/jsenecal/fastsmtp/labels/P0%3A%20critical)
- [P1: High](https://github.com/jsenecal/fastsmtp/labels/P1%3A%20high)
- [P2: Medium](https://github.com/jsenecal/fastsmtp/labels/P2%3A%20medium)
- [P3: Low](https://github.com/jsenecal/fastsmtp/labels/P3%3A%20low)
- [Security](https://github.com/jsenecal/fastsmtp/labels/security)
- [Performance](https://github.com/jsenecal/fastsmtp/labels/performance)
- [Bugs](https://github.com/jsenecal/fastsmtp/labels/bug)
- [Enhancements](https://github.com/jsenecal/fastsmtp/labels/enhancement)
