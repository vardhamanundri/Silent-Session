# SILENTSESSION companion exploit app

This is a minimal Android (Kotlin) app that performs the live Binder /
PendingIntent privilege-escalation attack against the *unmodified*
`SILENTSESSION.apk` ("Sentinel Recovery").

## Build
Drop `app/` into a standard Android Studio / Gradle project skeleton
(module `app`, package `com.attacker.relay`, `minSdk`/`targetSdk` 33),
copy in the two `.aidl` files under
`app/src/main/aidl/com/silentsession/vault/`, build, install alongside
the target app on the API 33 x86_64 emulator, and launch it.

## What it does
1. Declares `uses-permission` for `com.silentsession.vault.permission.ATTACH`
   (protectionLevel="normal", so any app can hold it) and binds to the
   exported `SessionService`.
2. `subscribe()`s a callback, then calls `open()`, which both creates a
   session (owned by this app's uid) and hands back 3 **mutable**
   `PendingIntent`s targeting the non-exported `RelayActivity`.
3. Fires each `PendingIntent` in slot order with a fill-in `Intent`
   supplying `EXTRA_SLOT` and `EXTRA_P` (the "p" proof value the real
   flow never sets). Because the PendingIntents aren't
   `FLAG_IMMUTABLE`, this is allowed, and because `send()` runs with
   the *creator's* identity, it starts the protected `RelayActivity`
   *inside the vault app's own process* -- which is the only thing
   that can ever satisfy `ISessionService.step()`'s same-uid check.
4. Each successful `step()` call advances the session; after all 3
   slots, the service seals a grant and notifies our subscribed
   callback with `ST_DONE` (code 2).
5. On that callback we call `fetch(id)` as the session's owner (us)
   and get the plaintext recovery token back.

The `EXTRA_P` proof values (`cdf2f9c4`, `d93cbea9`, `62e16c0f`) are
hardcoded after being recovered offline -- they're reversible
XOR-obfuscation baked into the APK's own `Keys.java`, not real
secrets, and don't depend on anything device-specific. See
`../solve/solve_offline.py` for the full derivation (which also
independently reproduces the final flag without needing the
emulator at all, since the seal key only depends on APK-embedded
material plus the app's own signing certificate).

## Flag
```
isfcr{h4nd0ff_tr4nscr1pt_s3al3d_by_th3_s1gn3r}
```
