# Rendezvous ownership and extraction

Source commit: `4f72ea86928666189b32f6f05c2c697a37341d06`. Nine cohesive core modules from `active-system/steward/` now live at `src/steward/`. The original state fixture is `tests/test_leases.py`; original README/dependency receipts are historical provenance under `legacy/`. Explicit earlier paths were included. All13 source/test/metadata blobs, modes and final paths were verified at mechanical baseline `53899db9e6c32da5996bf3df5f2a6e66e1d92525` before functional changes. Full source history remains privately preserved, with filtered commit/ref maps in phase29.

The functional commit changes two dependency imports to documented public Accounts interfaces, adds Python packaging and ports the console test runner. All original test classes/assertions and domain implementations remain unchanged. Baseline and installed-package lease tests both pass37. Nine installed modules import with original/recovery/primary/component source hidden. Websockets17.1 is explicit.

This component owns peer discovery/signaling, not official Chat/Chess content publication. Those remaining modules are preserved separately pending ownership. No listener, timer, operator, frontend boot integration or release is enabled. Signed wire, publisher/root custody, browser lifecycle, authenticated agent operations and real-network acceptance remain OPEN.
