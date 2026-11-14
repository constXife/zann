---
title: Chromium extension
description: Build, install and pair the Chromium browser extension.
---

# Chromium extension (#25)

`apps/extension` is a Manifest V3 toolbar popup with an optional per-site
field chooser. It connects only to the local
`com.rlyeh.zann` native host from [#199](browser-ipc.md), never to a server.
It implements password/TOTP fill, explicit review-and-save capture, and a local
password generator. Firefox packaging and Chrome Web Store publication remain
separate distribution work; this build targets Chromium on Linux and macOS.

## Build and load

Use Rust 1.92.0, Node 24 and the lockfiles in this repository:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.106 --locked
node apps/extension/build.mjs
cargo build -p zann-native-host --locked
```

The dependency-free runtime is emitted to `apps/extension/dist`. The build uses
Cargo.lock, a fixed wasm-bindgen ABI/tool version, canonical Rust IPC/crypto, and
packaged JS/CSS/assets only. Playwright is a pinned development-only dependency.
Do not commit generated WASM/glue or the unpacked distribution.

1. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**,
   and select `apps/extension/dist`. Copy its actual Chromium extension ID.
2. Install the native manifest for that ID using an existing private resolved
   Zann client root and the browser's real manifest directory. For example:

   ```sh
   target/debug/zann-native-host install /absolute/zann/root /absolute/browser/NativeMessagingHosts chromium ACTUAL_EXTENSION_ID
   ```

   Chromium IDs are exactly 32 lowercase characters `a`–`p`. Use the OS/browser
   directory from [Chrome's native messaging documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
   The installer never discovers HOME, widens an allowlist, or overwrites a
   conflicting operator file. It records the absolute executable location;
   rebuild/moving a binary does not silently relocate an installed manifest.
3. Open the native macOS/COSMIC client on that same root. In **Settings → Browser
   connections**, click **Connect browser** to display a one-time six-digit code.
4. Enter that code in the extension and click **Connect browser**. It expires in
   two minutes and permits five attempts total. A new native code replaces the
   previous one. Successful PAKE pairing consumes the code, saves native trust
   and installs the authenticated server pin in extension storage; the popup
   reconnects using that pin. No key copying/comparison or extra approval step.
5. Unlock and choose a vault in the native app. On an HTTPS login page, invoke
   the toolbar popup and click a matching login. The main document and its sole
   sign-in form need no selector; multiple forms require an explicit choice.
   The popup automatically searches every native page and shows all matching
   logins together; there is no **Search next page** action. Optional TOTP fills a visible `autocomplete="one-time-code"` input in that
   form. Filling never submits or clicks the page.

Identity creation, authenticated pin publication and forgetting serialize across popup windows
using the browser Web Locks API. Stale snapshots refuse rather than replacing a
newer identity; Forget installs the new identity with one atomic storage write.

Pairing survives extension updates as long as its local storage and extension ID
are retained. Clearing extension storage or changing the ID requires pairing
again. **Forget this connection** explicitly discards the client identity/pin;
revoke the old key in native Settings as well. A different server key is never
accepted automatically. Missing host/daemon, locked vault and pairing refusal
are visible states with an explicit reconnect action, not a cloud fallback.

## Suggestions beside fields

In the toolbar, expand **Suggestions beside fields** and select **Enable on this
site**. Chrome asks for optional access to that exact HTTPS host (all ports,
without subdomains). Focus a visible username/password field: Zann places its
key button at the field and opens matching accounts above/below it. Click a
login or use arrows and Enter; successful filling, Escape or an outside click
closes the chooser. The compact chooser is 320 CSS pixels wide (clamped to the
viewport), with 48-pixel account rows and height measured from its content;
three accounts take 188 pixels rather than the previous fixed 320. Username is
primary, record title secondary; long labels truncate visually but retain full
accessible text/tooltips. The key is a packaged SVG, not a font glyph. There is
no permanent keyboard hint, per-row return arrow, footer or TOTP checkbox.

Actions follow the focused field. A login/current-password field offers saved
accounts; an `autocomplete="new-password"` field offers **Create password → Use
password**, without login results or a native-vault dependency. An
`autocomplete="one-time-code"` field offers account selection with a 2FA label
and writes only its code, preserving username/password fields. Standalone OTP
forms are supported. The isolated DOM adapter owns/rechecks the field context;
the worker refuses actions inappropriate for that context. An entry without a
TOTP code reports an error instead of filling anything. The existing signed
native fill response still bundles password plus optional code: in OTP mode the
worker clears the unused password before injection and releases only the code
to DOM. Neither value enters the chooser or persistent extension storage.
Unlock/pair in the native application/toolbar if requested, then retry search.
Save remains the existing toolbar review flow below.

**Disable on this site** removes Chrome's grant, registered access and active
chooser. Chrome's extension site settings can revoke it too. Grants and dynamic
script registrations are Chrome-owned; extension storage has no duplicate host
list. Top-document forms only are supported inline; the toolbar's explicit
same-origin frame selection remains available. No default host access is granted.
Permission events register/install the adapter in the worker, even if Chrome's
consent sheet closes the toolbar popup. Activating an already-open granted tab
installs idempotently. Native/locked-vault errors preserve the admitted chooser's
retry action; they do not get confused with iframe admission failures.

## Save and generate

**Save login → Read selected form** reads only the selected form into a transient
masked review. Name the login, edit it if needed, then confirm saving. The request
contains typed title/username/password, a browser-observed context and the native
selection generation from the last query. Native code checks that selection
again under its context lease. It saves only the canonical HTTPS origin, stripping
path/query/fragment, and creates a new login through the same atomic
item/history/pending transaction used by native creation. Existing paths are
refused; capture does not update an existing credential or infer another vault.

Capture is manual: no submit interception, background page reads or prompt
injected into a site's document. Save errors after dispatch can be ambiguous;
check the native vault before another explicit save. Requests are never replayed
automatically, including after a native timeout or reconnect.

The generator projects `zann-ui-core::generator` through WASM, sharing the native
password policy and fallible OS entropy. It enables letters and digits plus the
optional symbol class, includes every selected class and shuffles the result.
The generated value remains transient until an explicit fill or save action.

## Permissions and hostile-page boundary

| Permission / CSP | Purpose |
| --- | --- |
| `activeTab` | Temporary page access following the toolbar action; independent of optional persistent grants. |
| `scripting` | Shared bounded isolated-world inspection/insertion and dynamic top-document content registration on granted hosts. |
| Optional `https://*/*` | Declares HTTPS capability only; the user grants one exact hostname at a time from the toolbar. No required host permission or subdomain wildcard. |
| `webNavigation` | Privileged frame URLs and stable document IDs; a page never supplies its claimed origin. |
| `nativeMessaging` | Launch the one registered local framing bridge. |
| `storage` | Persist versioned pairing identity/server pin and bounded opaque successful-fill MRU in `storage.local`, restricted to `TRUSTED_CONTEXTS`; never sync storage. |
| `script-src 'self' 'wasm-unsafe-eval'` | Execute packaged WASM and scripts. No JS eval or inline/remote code. Only `inline.html` is web accessible (dynamic URL); internal packaged resources remain private. HTTPS frame ancestors admit the chooser; no external messaging. |

Rust validates same-origin frame context and secure URL policy before any query,
fill or save. Before each DOM operation, Chrome's tab/top/frame URL and document
ID must still match the selection. Injection targets `documentIds`, not a reused
frame number; isolated code additionally checks URL continuity before insertion,
including same-document SPA changes. Mutation disconnecting a selected field
invalidates the chooser; toolbar actions on stale references refuse.

The inline iframe uses packaged extension code and its own internal runtime port,
never a window `postMessage` bridge. The worker admits a content producer by
extension ID, tab, top frame, stable document ID, current browser-observed URL
and exact site grant. A transient random capability associates the chooser;
its runtime sender must be an extension iframe in that same tab with a document
ID, and its packaged code reports the read-only browser `ancestorOrigins` (one
ancestor, the expected top origin). Chrome excludes extension-origin subframes
from `webNavigation`; the top document remains verified through that API.
`sender.url` is not used as the current page URL after `history.pushState`.
Metadata goes only to the admitted extension iframe. Secret values bypass it:
the worker sends them directly through the existing checked isolated injection.
Trusted chooser clicks or trusted key events in the adapter initiate release;
a page-script click or runtime/URL/gesture claim is not authority.

The iframe prevents page reads and CSS interference, but remains embedded in a
hostile document: a page can overlay, move or imitate it. Neither closed shadow,
`isTrusted`, random capabilities nor correct matching eliminates clickjacking.
This accepted tradeoff replaces the initial toolbar-only rule in ADR 0007;
users who do not grant a site keep the `activeTab` toolbar workflow.

Inspection examines at most 5,000 elements, 100 open shadow roots and 200 visible
inputs. It excludes disabled, readonly, hidden, transparent and inert fields,
groups by form/root, and requires one unambiguous login password target. Open
shadow DOM is supported; closed shadow roots, inaccessible/sandboxed documents,
unsupported form structures and cross-origin frames are refused. New-password
fields receive only explicitly generated values, not existing vault passwords.

The toolbar owns its own ephemeral Noise channel. Inline operations run in an
MV3 worker and use fresh authenticated channels without persistent results or
secrets. Closing a chooser destroys its channel/state; its maximum lifetime is
60 seconds, with at most 16 document controllers. Tabs becoming inactive,
navigation/SPA changes, revoked grants, identity replacement and detached fields
cancel inline authority. A worker restart loses ephemeral state; a fresh focus
reconnects instead of recovering/replaying an operation. Draft/generated values clear on
focus loss, discard and errors. Fill values are not returned by the DOM adapter
or cached in storage. WASM-owned plaintext input/output temporaries are zeroized after crossing the
edge. JS/browser message copies cannot promise forensic memory
erasure; the profile's client signing seed is itself authority for an approved
pairing and must be revoked if the browser profile is compromised. Vault/master
keys and raw payloads never enter this boundary. Site favicons are not fetched;
local branded icons and initials avoid adding network requests or permissions.

An idle native connection expires after five seconds. Inline search closes its
channel after returning complete metadata and reconnects only for a new fill. A new explicit popup
fill/save action may establish a fresh authenticated channel **before dispatch**;
an already-dispatched operation is never retried. Complete metadata search is
owned by `zann-client::browser_ipc::LoginSearch`: it serially consumes each opaque
cursor on the same authenticated connection, including empty pages and pages that
already contain matches. Identical item IDs are coalesced; conflicting metadata,
a repeated cursor or a changed native selection poisons the search. The popup
shows a searching state until the terminal page arrives, then publishes one
complete result. Errors discard all partial results and require **Refresh**;
cursors are never resumed on another connection.

Browser document/URL identity is checked before and after every page. Navigation,
SPA URL changes, tab removal and closing the popup cancel the search and clear
metadata; no fill/save is automatically dispatched. The shared flow accepts only
monotonic elapsed time from the browser's `performance.now()` clock and has a
30-second deadline, at most 4,096 native pages and 8,192 unique matches. Each
native query still reads at most 32 candidates. Exceeding a bound is an explicit
error, never a truncated successful result.

## Verification

```sh
cd apps/extension
bun install --frozen-lockfile
bun run test
node node_modules/playwright/cli.js install chromium
bun run build
# from the repository root, once:
cargo build -p zann-native-host --locked
# back in apps/extension:
bun run test:browser
```

The Chromium integration test runs real packaged WASM, the native host process,
a Unix socket and a disposable daemon/vault. To avoid changing the developer's
browser registration, its test harness replaces only the browser's native host
launcher with a process bridge. The toolbar popup is opened as a tab: a test-only manifest
grants fixture hosts, and its tab query selects the fixture tab. URL/document
observations and injection still use actual Chrome APIs. The inline test also substitutes only the worker native launcher; its iframe,
runtime ports, browser document IDs, ancestor-origin checks, Rust search and
checked injection are real. These overrides never
enter the shipped package; toolbar permission granting and OS registration are
not claimed as automated end-to-end coverage. The installer has independent
scope/permissions/idempotency tests. Tests never open an existing browser profile.

Additional regressions cover pin refusal/poisoned client state, no fill on query,
password+TOTP insertion, explicit save, generator, complete automatic search across
empty/matching native pages, URL-change cancellation, storage
contents, no window/external message entry points, synthetic inline click refusal,
keyboard selection, inline TOTP/generation, detached nodes and SPA reattachment,
exact-host grant/revocation and registration unit tests, no replay after disconnect, selection
changes, and transaction rollback when pending-change insertion fails. CI builds
and uploads the unpacked artifact and runs the browser test on Linux.

Manual Chrome check (2026-11-14): loaded the unpacked update with the existing
native pairing; granted, revoked and re-enabled HTTPS localhost access through
Chrome's UI. A fresh local form showed all three fictional matching logins at
field focus. Selecting the test login filled previously empty username/password
fields and closed the chooser. Native auto-lock was visible as an explicit
unlock/retry state. Certificate interstitials and master-password entry were
handled by the user; no global certificate exception or CA was installed.


## Popup presentation

The popup presents one task at a time: unpaired browsers see the code entry,
native/locked/revoked states show the relevant retry or reconnect action, and a
ready page shows its hostname and matching accounts (username first). Save and
generation are secondary actions with a back-to-logins control. Settings holds
site suggestions and connection management; persistent banners, the connection
accordion, the always-visible page/form selectors and the three-tab bar are
removed.

Page/document failures are distinct from native connection failures. A browser
error document is refused before inspection; a failed script injection or Rust
context admission becomes a readable `PageError` retaining its original cause.
The popup shows a page-only empty state and keeps native trust/authorization.
No frame IDs, raw browser errors or irrelevant fill controls appear in that
state. Retrying rescans the current browser-observed document without replaying
fill/save. Page navigation still clears every partial result/draft immediately.

A sole form is the only automatic form selection; multiple forms expose a
chooser and disable login release until selection. An optional collapsed page
section chooser retains explicit frame selection, including the same-origin
admission check. No iframe fallback or automatic DOM write is introduced.
The TOTP option is visible only for the selected form's detected OTP field;
requesting its code still requires the explicit checkbox and fill gesture.
Chrome permissions, Rust matching/pairing, native release boundaries and secret
storage remain unchanged. Browser regressions cover this presentation alongside
complete search, capture, generation, strict document checks and inline flows.


## Local successful-fill ordering

Popup and inline lists use the same Rust ranking owner after complete search:
exact URL, same origin, same registrable domain, configured equivalent domain,
then an otherwise admitted regex match. Within a quality group, the most recent
successful DOM autofill comes first. Unused ties retain native ordering. These
priorities refine matching; they do not broaden eligibility or change gesture,
frame, HTTPS or native authorization rules. Match quality is native metadata;
no shell reimplements URL/PSL rules. The strict Pre-GA `BrowserMatch` record adds
`match_quality` directly, so rebuild/reload native service and extension together.

The profile-local `autofillUsage` record is a strict Rust-owned versioned JSON
snapshot. Its at-most-4096 MRU entries contain only local daemon public key,
storage/vault/item identifiers, ordered newest first. There are no timestamps,
frequency counts, URLs, titles, usernames, credentials or search-result cache.
Clock changes cannot affect order. This history is local to this Chrome profile
on this device and never enters vault items, pending changes, server sync or
`storage.sync`. Least-recent entries are evicted at the bound.

One shared adapter records only after isolated-world insertion returns success,
for password/login or OTP fills. Querying, clicking without admission, requesting
a native secret, capture/save, generation, rejected/stale DOM targets or ambiguous
injection do not record use. Password/code copies are cleared before metadata
storage I/O. A usage-write failure reports that fields were already filled and
never replays them. Lists consume updated usage on their next complete search;
current rows do not jump under the user's pointer after a fill.

The identity Web Lock serializes both surfaces' metadata writes with explicit
Forget. Scope excludes transient native generation, so locking keeps recency;
other roots/storages/vaults cannot influence each other. Forget removes usage
before atomically replacing the browser identity. A crash during reset can leave
the prior identity without history, never re-create history for a new identity.
Late writes from an old identity are refused. Invalid/future/oversized/duplicate
history is surfaced explicitly, never replaced with empty history automatically;
Forget is the existing explicit reset action. Browser regressions cover both
surface directions, reopening, refused DOM insertion, synthetic clicks, save /
generation non-use, and reset; Rust tests cover precision, scope and retention.


## Filtering and virtual rows

A search field appears when the full matching list exceeds that surface's
viewport (five 48-pixel rows in popup, four in inline). It searches only the
public record title and public username, ignoring case and surrounding query
whitespace. `zann-ui-core::filter::TextQuery` is shared with the native list
filter; `login_list::LoginList` preserves native match-quality/MRU order and
maps filtered positions back to the original metadata. WASM exports at most 64
rows per projection. Queries and filtered results are transient and are cleared
on replacement/navigation/close, never persisted or sent to the native service.

Both surfaces use one DOM component and stylesheet. A virtual spacer retains
scroll position while only the viewport plus two overscan rows per side are
mounted: at most nine popup rows or eight inline rows. Fixed row height is
owned by the component and bound to CSS. Filtering resets selection and scroll,
shows a result count/empty state, and invalidates detached row handlers. No
manual next-page control or streaming/partial result changes are introduced;
complete native search and ranking still precede local filtering.

Arrow keys, Page Up/Down and Home/End navigate the filtered list; Enter selects
its active item. Text-caret Home/End remain native when editing a nonempty
query, and IME composition cannot trigger fill. Combobox/listbox semantics use
active-descendant, selected position and total-set size for virtual rows. A
short popup list remains keyboard-focusable without a search field. Native
button Enter keeps its existing trusted-click path. Selection only sends the
chosen original item ID through the existing authorized fill flow; empty
results, synthetic clicks and stale row handlers cannot release a credential.
The inline document/ancestor/gesture checks and secret-delivery route are unchanged.

The real Chromium fixture can create 1024 matching logins. Regressions verify
bounded DOM after deep scrolling, username/title filtering, no-result Enter,
keyboard selection beyond the initial window, correct insertion in both
surfaces and no usage update from filtering. Pure presentation tests also cover
8192 entries, Unicode/case handling, stable ordering and invalid window/query
bounds. The existing fill/save/generate/OTP/document/pairing regressions remain.
