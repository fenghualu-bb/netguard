# NetGuard repository maintenance

## Scope

This repository is a sanitized Windows source snapshot. Read README.md and docs/OPERATIONS.md before modifying deployment or protection behavior. Repository tests use fixtures; they do not prove the current machine is protected.

## Safety constraints

- Diagnose read-only first. Separate verified state, assumptions and untested leak paths.
- Keep the base killswitch, ClaudeGuard protection and the configured whitelist intact. Never use disable, guard-off or DIRECT to make a failure look resolved.
- Before restarting FlClash, toggling TUN, reloading proxy configuration/subscriptions, changing adapters/routes, or installing/removing the ClaudeGuard network helper, explain the real-IP risk and wait for explicit confirmation that other network apps are closed.
- The user personally confirms UAC. Never bypass it or silently clear a lockdown. Manual release must retain the target, helper, rule and dual-egress checks.
- Back up changed deployment files before replacement. Keep PowerShell source UTF-8 with BOM and use `@(...)` for array boundaries. Do not use smart quotes as PowerShell string delimiters.
- Changes to the workbench must keep every button reachable at 200% scaling.
- Preserve WFP transactions and the same Global state mutex. Do not bypass serialization, grant Everyone access, or mistake extra DENY rules for weakened protection.

## Repository hygiene

- Do not commit runtime config/state, proxy/node/subscription data, tokens, logs, manifests, backups, screenshots or personal-memory records, even to a private remote.
- Keep tracked test IPs and paths synthetic. Do not copy the machine-specific full operations manual into Git.
- Preserve third-party attribution and LICENSE files. The ClaudeGuard snapshot requires compatible upstream dependencies and manual application; never overwrite a running guard as part of a Git sync.
- Run applicable offline tests, parse/BOM checks and layout checks before reporting success. For an installed repair, also validate real protected runtime state per the operations document.
