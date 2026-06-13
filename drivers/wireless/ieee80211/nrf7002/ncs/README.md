# Vendored NCS nrf_wifi firmware stack

The nRF7002 driver is a NuttX OSAL/netdev port layered over the Nordic NCS
`nrf_wifi` FMAC firmware stack.  The OS-agnostic parts of that stack are
vendored into this repository:

- **Sources** — the `ncs_*.c` files in the parent directory are the NCS
  `nrf_wifi` C sources (renamed flat for the NuttX build).  They are
  **BSD-3-Clause, Copyright (c) Nordic Semiconductor ASA**; the original
  per-file license headers are retained.
- **Headers** — this `ncs/` directory mirrors the NCS `modules/lib/nrf_wifi`
  include tree (`os_if/`, `hw_if/`, `fw_if/`, `bus_if/`, `utils/`).

Provenance: NCS v3.2.4, `modules/lib/nrf_wifi`.

A small number of NuttX-port fixes were applied to the vendored sources
(inline RPU event processing in the IRQ handler, scan/auth CMD_STATUS
deadlock recovery, a keep_alive_period log typo).  Each is marked with a
`NuttX port:` comment at the change site.

## Firmware blob (not distributed here)

The RPU requires a firmware patch (`nrf70.bin`).  It is **Nordic-proprietary
(LicenseRef-Nordic-5-Clause)** and is therefore **not** included in this
repository.  Generate the in-tree blob from your nRF Connect SDK before
building:

```sh
drivers/wireless/ieee80211/nrf7002/tools/gen_fw_blob.sh \
    <ncs>/nrfxlib/nrf_wifi/bin/ncs/default/nrf70.bin
```

This writes `nrf70_fw_patch.inc` and `nrf7002_fw_blob.c` (both git-ignored);
the driver links `g_nrf70_fw_patch[]` / `g_nrf70_fw_patch_len` from them.
Without this step the link fails with an undefined reference to those symbols.
