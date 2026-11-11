# Source snapshot

Snapshot: 2026-11-11. NetGuard 1.3.5.

Main application/admin sources and the ClaudeGuard runtime snapshot are copied byte-for-byte.
Test fixtures use a reserved documentation IP; PowerShell files retain a UTF-8 BOM.
The ClaudeGuard test loader is subsequently adjusted to test the tracked runtime snapshot.
Runtime configuration, logs, helper manifests, backups and local AI memory are excluded.

| Relative file | Installed SHA-256 | Export SHA-256 |
|---|---|---|
| `workbench.pyw` | `4c650e7e7a1359a56032518242db04032b714c52731977278e50c8f64cd4480c` | 4c650e7e7a1359a56032518242db04032b714c52731977278e50c8f64cd4480c |
| `install.ps1` | `94393b1e3145db8ab28ef4d46f9be57144ebd43c386b4370a2ddf2aa3b06374a` | 94393b1e3145db8ab28ef4d46f9be57144ebd43c386b4370a2ddf2aa3b06374a |
| `admin/netguard.ps1` | `3fe6d93150399d9032e9c134454471dd7778462b450c7c4e6e4fef6b277642c4` | 3fe6d93150399d9032e9c134454471dd7778462b450c7c4e6e4fef6b277642c4 |
| `admin/netguard_wfp.cs` | `6d3f69f5e73852c1c77fef99f341ac7364a9ab6eba726f518fcc511e943a0e59` | 6d3f69f5e73852c1c77fef99f341ac7364a9ab6eba726f518fcc511e943a0e59 |
| `tests/check_layout.py` | `29f311a4f9d5280c172fe37486a5cf2e1aaa77817ec59b45159ab090005845a3` | 0ad6e2aa3a6b3425bec418aa0c55271a1eadcee126fe0aae9612ec9a1b8013a5 |
| `tests/test_admin.ps1` | `8be585424d47ef12269e10ae84c87223d4a9ac06002a1df5c4ea91162aa0fcbe` | 9d7896909512ac042ad53b9223138c49ae9583865ed78d5fced9e2709696bbdd |
| `tests/test_claudeguard_patch.py` | `daae72cef60dcea78cb500aedf4135825daa1fa9b8c128337202639ca00676c7` | 2f05236c2aeb640ba1725addb894672887fd3545bc16db535201507a817601c8 |
| `tests/test_isolation_sync.ps1` | `97961cda00469dc3fbf1b97c18dd19dce6bb638af13f2a6b90a0cd22daf2e96a` | 2cd64cc3d3a9fcf2bc8b76f0bde537f26ae534abb85d669a0c84f9fb3533d36a |
| `tests/test_release_requirements.ps1` | `25a04ceb33686ac4a98da451c57ca19c65ce2cc539f869ac32c47a7766a92c61` | 21e2ff9f6a0b9bef09a4ef477c500f9423991a7fec2e3519e76254d263cdf86d |
| `tests/test_state_mutex.ps1` | `1fe0a089738746bf6db42f90daedf5cc4bd2a144f68c64ac0161b31f8f3605c4` | 1fe0a089738746bf6db42f90daedf5cc4bd2a144f68c64ac0161b31f8f3605c4 |
| `tests/test_store_lifecycle.ps1` | `724e085c62dbed70360d67d3b423c171a630ae26b7d533b775643fcf57248b58` | 85c5fd7d92f4d259869f4c31e05e494b28fb96319169d94f6df79515bc92964b |
| `tests/test_workbench.py` | `8e12c4128b974c1b3206e3b2565a9baa5b520f4ba67280bb29c940bfc03d354b` | f764967af27c40d74cc224bfda1e21b41101fedc6d35c8757b56d6740902afc6 |
| `patches/claudeguard/runtime.py` | `3886e3fff60eb5b1b81164244b6d2026c97362c543d9fe0882c3123fbcec2912` | 3886e3fff60eb5b1b81164244b6d2026c97362c543d9fe0882c3123fbcec2912 |
| `patches/claudeguard/LICENSE` | `7292091c615fd99c741ad16cfdd74ad96ad48f913eefa07c50ad957bf678b70d` | 7292091c615fd99c741ad16cfdd74ad96ad48f913eefa07c50ad957bf678b70d |
