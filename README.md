# DanzKu PQ Global Hook v0.3

Experimental ARM64 MediaTek PQ hook.

Target library:
`/vendor/lib64/hw/mt6789/vendor.mediatek.hardware.pq@2.15-impl.so`

Target function:
`PictureQuality::enableDisplayColor(unsigned int)`

## Implemented

- ARM64 injector attaches to the running MediaTek PQ service with ptrace.
- Injector performs a remote `dlopen()` of `libdanzku_pq.so`.
- The injected library locates the mapped PQ implementation.
- It patches the verified `enableDisplayColor` offset (`0x37758`).
- An ARM64 trampoline preserves the first 16 bytes and returns to the original function.
- The hook forces the argument to `1` and then calls the original function.
- Persistent diagnostics are written to `/sdcard/DanzKu_PQ_Global_Hook.txt`.

## Important device-specific assumption

The target symbol offset `0x37758` comes from the exact `vendor.mediatek.hardware.pq@2.15-impl.so` build previously inspected on the target device. If that vendor library changes, the offset must be re-verified before using this module.

The injector is ARM64-only and requires root/ptrace permission.

## Log

`/sdcard/DanzKu_PQ_Global_Hook.txt`

Successful installation should contain:
- `remote-dlopen status=SUCCESS`
- `DanzKu PQ library loaded; installing enableDisplayColor hook`
- `HOOK ACTIVE ...`

When the target function executes:
- `HOOK enableDisplayColor(1)` or `(0)`

This is experimental low-level code. Keep a recovery path (ADB/root shell) available in case the vendor PQ service crashes or restarts.


## v0.3.3 fix
- Corrected ARM64 remote-call sequence so the original PC instruction is not immediately replaced by a BRK-only path.
- `dlopen()` success now requires a positive handle and verification that `libdanzku_pq.so` appears in the target `/proc/<pid>/maps`.
- `service.sh` and native binaries are packaged with executable permissions, with a `post-fs-data.sh` permission safeguard.
