# Security hardening — divergence from upstream

This fork tracks [lbjlaq/Antigravity-Manager](https://github.com/lbjlaq/Antigravity-Manager)
and carries a set of security fixes on top of it. This file exists so that a future
`git merge upstream/main` is easy to reason about: it lists every place where this
fork deliberately differs, and why.

None of these changes remove a feature. Multi-account management, per-account device
fingerprints, the local OpenAI/Claude/Gemini API, the CLI integrations and the
headless/WSL install path all behave as before.

## What changed

### 1. CORS is no longer open to every website
`src-tauri/src/proxy/middleware/cors.rs`, `src-tauri/src/proxy/config.rs`

The proxy reflected any `Origin`. Combined with the desktop default of
`auth_mode: auto` → `off`, that meant **any web page you visited could POST to
`http://127.0.0.1:<port>/v1/chat/completions` and read the answer**, spending your
Google quota on your accounts.

Now only origins listed in `security_monitor.cors_allowed_origins` are allowed.
The single entry `"*"` restores the old behaviour for anyone who knowingly wants it.

CORS is a browser-only mechanism. Native clients (Codex, Claude Code, opencode,
droid, Cline, Cherry Studio…) never send preflights and are unaffected. The desktop
UI uses Tauri IPC, and the headless Web UI is same-origin — neither needs an entry.
Only browser-tab clients (LobeChat, NextChat, Open WebUI in a browser) must be listed.

Takes effect on proxy restart.

### 2. `X-Forwarded-For` is only believed from a configured reverse proxy
`src-tauri/src/proxy/middleware/ip_filter.rs`, `src-tauri/src/proxy/middleware/auth.rs`

`extract_client_ip` trusted `X-Forwarded-For` / `X-Real-IP` unconditionally. Any
client could therefore pick its own apparent IP and walk past the IP blacklist, past
the IP **whitelist**, and past the per-token IP binding, while poisoning the security
logs.

`extract_client_ip_with_trust` consults those headers only when the request really
comes from an address listed in `security_monitor.trusted_proxies`. Default is empty:
only the TCP peer address counts. Put your reverse proxy there (`127.0.0.1`, `::1`
for nginx/Caddy/cloudflared on the same host) to get real client IPs in the logs again.

### 3. OAuth callback validates the `state` parameter
`src-tauri/src/proxy/server.rs`, `src-tauri/src/modules/oauth_server.rs`

`/auth/callback` is public by necessity and ignored the `state` parameter (the field
was literally `#[allow(dead_code)]`). Any web page could fire
`GET /auth/callback?code=<attacker's code>` at the loopback port and graft the
**attacker's** Google account onto the victim's pool, after which the victim's prompts
could be routed through an account the attacker controls.

The desktop flow already validated `state` in `oauth_server.rs`; the check is now
exposed through `verify_pending_state()` and applied to the proxy route used in
Web/Docker mode too.

### 4. The admin API is behind the IP filter
`src-tauri/src/proxy/server.rs`

`ip_filter_middleware` was layered only onto the AI proxy routes. `/api/*` — which
exposes `/api/accounts/export`, returning **every Google refresh token in clear
text** — had no IP filtering at all. It now gets the same layer, running before
`admin_auth_middleware`.

### 5. Credential comparison is constant-time
`src-tauri/src/proxy/middleware/auth.rs`

`==` on the API key / admin password returns at the first differing byte, leaking the
matching prefix length through response timing. `constant_time_eq` compares every byte.

### 6. `/internal/*` is restricted to loopback
`src-tauri/src/proxy/middleware/auth.rs`

`/internal/warmup` bypassed authentication unconditionally, so on an exposed instance
anyone could trigger a warmup across every account and burn quota. It is called by
this process over loopback (`modules/quota.rs`), so the bypass now requires a loopback
peer; anything else gets a 404.

### 7. cloudflared refuses to publish an unauthenticated proxy
`src-tauri/src/commands/cloudflared.rs`, `src-tauri/src/proxy/server.rs`

The tunnel forwards `https://<random>.trycloudflare.com` to `http://localhost:<port>`.
Since it arrives over loopback, `allow_lan_access` stays false and `auth_mode: auto`
resolves to `off` — the tunnel published a **completely unauthenticated gateway to
every Google account, to the whole Internet**, with no warning.

`ensure_tunnel_auth_configured()` now blocks the start until an API key (or admin
password) exists and authentication is enabled. The tunnel itself is unchanged.

### 8. Token and config files are owner-only
`src-tauri/src/utils/fs.rs`, `src-tauri/src/modules/account.rs`

`accounts.json`, the per-account files (Google refresh tokens in clear text) and
`gui_config.json` (API key, admin password, proxy-pool credentials) were written with
the default umask — typically `0644`, readable by every other local user. They are now
created `0600`, and the data directories `0700`.

### 9. macOS Keychain access is scoped to the IDE
`src-tauri/src/modules/integration.rs`

`security add-generic-password … -A` let **any** local application read the Google
credential with no prompt. Replaced by `-T <app>` for each Antigravity installation
actually found on the machine, so account switching stays seamless but applications
using the Keychain API no longer get a free read.

**This mitigation is partial, by design.** Because the item is created by shelling out
to `/usr/bin/security`, that binary is automatically added to the item's ACL — which is
also what keeps this app's own read path working. A determined local process can still
read the credential by invoking the `security` CLI itself. Closing that gap requires
creating the item through the native Keychain API (the `security-framework` crate) so
that *this application* is the ACL owner; that is a refactor, not a patch, and was left
out of scope. `-T` is nonetheless strictly better than `-A`.

### 10. No default credentials in Docker
`docker/docker-compose.yml`, `docker/docker-compose.fork.yml`

`API_KEY=${API_KEY:-test}` and `:-changeme` shipped a guessable password guarding an
admin API that exports every refresh token — on a compose file that binds all
interfaces. Both now use `${API_KEY:?…}`, which refuses to start until a real secret
is provided.

### 11. Error text escaped in the OAuth callback pages
`src-tauri/src/proxy/server.rs`

Upstream error strings were interpolated raw into HTML. Now escaped via `html_escape`.

## Known issues deliberately NOT changed

These were found during the audit and left alone on purpose — fixing them would cost
functionality or needs a refactor rather than a patch.

- **`security … -w <value>` passes the token as a command-line argument** on macOS, so
  it is briefly visible in `ps` to other local users. The `security` CLI offers no
  stdin path for this; fixing it properly needs a native Keychain binding
  (`security-framework` crate). Linux already uses stdin.
- **cloudflared is downloaded without checksum or signature verification**
  (`modules/cloudflared.rs`). The URL is Cloudflare's official GitHub release over
  HTTPS; pinning would need a trustworthy checksum source and would break on each
  upstream release.
- **`install.sh` removes the macOS quarantine attribute** (`sudo xattr -rd`). Required
  because the app is unsigned; removing it would break installation on macOS.
- **`postMessage(..., '*')` in the OAuth success page.** The payload carries no secret,
  and restricting the target origin risks breaking the auto-refresh across the
  `tauri://` / `http://localhost` origin boundary.
- **`query_transit_info(url, key)`** (`commands/mod.rs`) takes an arbitrary URL, i.e.
  server-side request forgery — but it is admin-authenticated and it is the mechanism
  of the third-party relay balance feature.
- **Hardcoded Google OAuth `client_id` / `client_secret`, TLS fingerprint spoofing via
  `rquest`, device-fingerprint falsification.** These are the purpose of the tool, not
  defects. They are also the most likely real-world risk to you: **Google account
  suspension**. Use throwaway accounts.

## Recommended configuration

```jsonc
// gui_config.json → proxy
{
  "auth_mode": "strict",          // not "auto"
  "api_key": "<openssl rand -hex 32>",
  "security_monitor": {
    "trusted_proxies": [],        // add "127.0.0.1" only if behind a reverse proxy
    "cors_allowed_origins": []    // add browser-client origins only if you use one
  }
}
```

Docker: always set `API_KEY`, keep `ABV_BIND_LOCAL_ONLY=true` unless you really need
remote access. On Unix, the data directory is now `0700`; verify with
`ls -ld ~/.antigravity_tools`.
