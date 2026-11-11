# macOS parity acceptance gate

All real-machine rows are **NOT RUN** until evidence is collected on the target M2/macOS15.8.3 machine. Windows historical tests are not Mac results. Never turn these labels green merely because a framework preference is enabled.

| Requirement | Acceptance evidence | Current real-Mac status |
|---|---|---|
| Valid production signing | Correct Team ID, authorized profiles, codesign and notarization checks | NOT RUN |
| User approval | Both extensions and root helper actually approved/registered | NOT RUN |
| Active filtering | Known canary traffic demonstrably allowed/dropped by both providers | NOT RUN |
| Exact proxy and TUN | Actual current core identity, ownership and interface index; reject unrelated utun | NOT RUN |
| IPv4 direct bypass | Bound physical-interface HTTPS blocked, proxied trace works | NOT RUN |
| IPv6 direct bypass | Equivalent IPv6 physical test blocked; no assumed IPv4-only coverage | NOT RUN |
| DNS and LAN | Bound physical UDP/TCP DNS blocked; approved LAN still works | NOT RUN |
| Claude desktop + helpers | Every current trusted native identity covered | NOT RUN |
| Claude native CLI | Native signer/hash identity identified; generic interpreters not globally trusted | NOT RUN |
| Existing streams | Lockdown cuts already-open Claude streams, not only new connections | NOT RUN |
| Exit whitelist | Both current exits verified; missing/disagreeing values cannot release | NOT RUN |
| Proxy/TUN failure | Stop proxy/TUN under agreed safe procedure, no physical fallback | NOT RUN |
| GUI/helper crash | Crash each independently, no stale permission or false green | NOT RUN |
| Provider crash | Crash packet and socket providers independently, prove actual fail-closed behavior | NOT RUN |
| Sleep/wake and network change | Repeat Wi-Fi/Ethernet, wake, interface recreation with no bypass | NOT RUN |
| App/CLI update | Identity change is validated, new files cannot bypass coverage | NOT RUN |
| Authorization | Unsigned/wrong-team/XPC peers and unprivileged state tampering rejected | NOT RUN |
| Manual release | Persistent lock remains until authenticated fresh revalidation succeeds | NOT RUN |
| Recovery | User-controlled safe rollback retains protection; no silent disable/DIRECT | NOT RUN |
| Usability | Native resizing, keyboard/VoiceOver, Retina and clear readiness blockers | NOT RUN |

Critical failures keep deployment blocked. An enabled filter preference, source compilation, a sample UI, SDK availability or an IP probe alone is insufficient evidence. If provider-crash semantics fail, revise the enforcement architecture rather than report parity or hide the failed row.
