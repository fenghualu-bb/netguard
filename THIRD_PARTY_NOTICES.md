# Third-party notices

`patches/claudeguard/runtime.py` is a locally modified snapshot of [ivblz/ClaudeGuard](https://github.com/ivblz/ClaudeGuard). The upstream MIT license, including its original copyright notice, is retained in `patches/claudeguard/LICENSE`.

Local modifications add structured protection events and severity-based process termination. Network-helper requests remain independent of the soft termination delay. This is a historical compatible-source snapshot, not a claim of compatibility with every future upstream version. Back up and compare before applying it; replacing code and restarting a guard require the deployment safety procedure.

NetGuard integrates with external ClaudeGuard and [FlClash](https://github.com/chen08209/FlClash), and its WFP design was informed by [WireGuard for Windows](https://github.com/WireGuard/wireguard-windows/tree/master/tunnel/firewall). FlClash, WireGuard binaries and their source trees are not bundled. NetGuard's own code is licensed under the MIT license in [`LICENSE`](LICENSE); this notice does not modify any upstream license.
