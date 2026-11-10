# Source snapshot

Snapshot: 2026-11-10. NetGuard 1.3.4.

Main application/admin sources and the ClaudeGuard runtime snapshot are copied byte-for-byte.
Test fixtures use a reserved documentation IP; PowerShell files retain a UTF-8 BOM.
The ClaudeGuard test loader is subsequently adjusted to test the tracked runtime snapshot.
Runtime configuration, logs, helper manifests, backups and local AI memory are excluded.

| Relative file | Installed SHA-256 | Export SHA-256 |
|---|---|---|
| `workbench.pyw` | `2c9b93a35975b2ac182c2bcd6dad2b870cbf1870562796541b7c1e7c50f309fc` | 2c9b93a35975b2ac182c2bcd6dad2b870cbf1870562796541b7c1e7c50f309fc |
| `install.ps1` | `94393b1e3145db8ab28ef4d46f9be57144ebd43c386b4370a2ddf2aa3b06374a` | 94393b1e3145db8ab28ef4d46f9be57144ebd43c386b4370a2ddf2aa3b06374a |
| `admin/netguard.ps1` | `b8ae2c7cefe999b533601d4d0fcd34e3f8c56562584c10cc68c5706af3766f6f` | b8ae2c7cefe999b533601d4d0fcd34e3f8c56562584c10cc68c5706af3766f6f |
| `admin/netguard_wfp.cs` | `6d3f69f5e73852c1c77fef99f341ac7364a9ab6eba726f518fcc511e943a0e59` | 6d3f69f5e73852c1c77fef99f341ac7364a9ab6eba726f518fcc511e943a0e59 |
| `tests/check_layout.py` | `29f311a4f9d5280c172fe37486a5cf2e1aaa77817ec59b45159ab090005845a3` | 0ad6e2aa3a6b3425bec418aa0c55271a1eadcee126fe0aae9612ec9a1b8013a5 |
| `tests/test_admin.ps1` | `364b960ac97cce9e1142587c65b1dec0be4c2146625c22927502cfd56af62647` | 3baa3d0a8ce5aa65c7744f9b638d623ce61a2b208ee3c7006c57ab963b9f611b |
| `tests/test_claudeguard_patch.py` | `daae72cef60dcea78cb500aedf4135825daa1fa9b8c128337202639ca00676c7` | 2f05236c2aeb640ba1725addb894672887fd3545bc16db535201507a817601c8 |
| `tests/test_isolation_sync.ps1` | `7127af1de0bf343dc2005a37c3f582b19d1cabbeadd12558cdd8054699c40dfa` | 4c601c7de0b6965e3ae0824d2ec5b07a1a47cc43e8ac8d3d5b79a544bc0274cc |
| `tests/test_release_requirements.ps1` | `25a04ceb33686ac4a98da451c57ca19c65ce2cc539f869ac32c47a7766a92c61` | 21e2ff9f6a0b9bef09a4ef477c500f9423991a7fec2e3519e76254d263cdf86d |
| `tests/test_state_mutex.ps1` | `1fe0a089738746bf6db42f90daedf5cc4bd2a144f68c64ac0161b31f8f3605c4` | 1fe0a089738746bf6db42f90daedf5cc4bd2a144f68c64ac0161b31f8f3605c4 |
| `tests/test_store_lifecycle.ps1` | `724e085c62dbed70360d67d3b423c171a630ae26b7d533b775643fcf57248b58` | 85c5fd7d92f4d259869f4c31e05e494b28fb96319169d94f6df79515bc92964b |
| `tests/test_workbench.py` | `cabb05782cfa5f617d14b81b47f2fbfe793343b5eaf924ff718b10cd606fff28` | 4a9cf040417b9563ce0ac02cf073bd220ce8ba00d7a4b899bfdf59b48da38fad |
| `patches/claudeguard/runtime.py` | `3886e3fff60eb5b1b81164244b6d2026c97362c543d9fe0882c3123fbcec2912` | 3886e3fff60eb5b1b81164244b6d2026c97362c543d9fe0882c3123fbcec2912 |
| `patches/claudeguard/LICENSE` | `7292091c615fd99c741ad16cfdd74ad96ad48f913eefa07c50ad957bf678b70d` | 7292091c615fd99c741ad16cfdd74ad96ad48f913eefa07c50ad957bf678b70d |
