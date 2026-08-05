# MyCoRe WAF Plugin

A Web Application Firewall (WAF) plugin for [MyCoRe](https://www.mycore.de/) applications. It protects against bot attacks by issuing a **Proof of Work (PoW)** challenge that must be solved in the browser before any request is served. Legitimate search engine crawlers are let through via an allow list based on IP ranges, paths, or verified reverse DNS lookups (only triggered when the User-Agent identifies a known bot).

## How it works

1. An incoming request hits the `WAFFilter`, which is automatically registered for all URLs (`/*`) on startup.
2. The filter checks allow lists in order: path → IP range → browser sub resource → valid `WAF-PASSED` cookie → known bot reverse DNS. Matching requests pass through immediately.
3. For the reverse DNS check, the User-Agent is inspected first. Only if it matches a known bot pattern (e.g. `Googlebot`, `bingbot`) is the expensive DNS lookup performed and the resolved hostname verified.
4. If no allow list matches, the client is redirected to the PoW challenge page.
5. The browser solves the SHA-256 PoW challenge in JavaScript and submits the solution.
6. The server validates the solution and, if correct, sets the `WAF-PASSED` cookie. The client is then redirected to the originally requested URL.
7. After too many failed attempts the client is shown a failure page.

```
Request
  │
  ├─ Path allow list match?              ──yes──> pass through
  ├─ IP allow list match?                ──yes──> pass through
  ├─ Allowed browser sub resource?       ──yes──> pass through
  ├─ Valid WAF-PASSED cookie?            ──yes──> pass through
  ├─ Known bot UA + reverse DNS match?   ──yes──> pass through
  ├─ Challenge solution submitted?       ──yes──> validate → set cookie → redirect to original URL
  ├─ Challenge page requested?           ──yes──> serve PoW challenge page
  └─ (anything else)                     ──────> redirect to challenge page
```

## Installation

Add the JAR to the lib directory of your MyCoRe application. 
The plugin registers itself automatically via `MCR.Startup.Class` — no additional `web.xml` changes required.


## Configuration

All settings are optional. The plugin works out of the box with sensible defaults.

### General

| Property          | Default | Description                         |
|-------------------|---------|-------------------------------------|
| `MCR.WAF.Enabled` | `true`  | Enable or disable the WAF entirely. |

### Allow Lists

Requests matching any allow list entry bypass the PoW challenge completely.

| Property                        | Default                                             | Description                                                                                                              |
|---------------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.AllowedIPs`            | _(none)_                                            | Comma-separated list of IPs or CIDR ranges, e.g. `127.0.0.1,192.168.1.0/24`.                                            |
| `MCR.WAF.AllowedPaths`          | `/robots.txt,/sitemap.xml,/favicon.ico,/api/.*,...` | Comma-separated list of Java regex patterns matched against the request path (without context path).                     |
| `MCR.WAF.KnownBotUserAgents`    | Google, Bing, Baidu, Apple bot UA strings           | Comma-separated User-Agent substrings (case-insensitive). Only requests whose UA matches one of these strings trigger a reverse DNS lookup. |
| `MCR.WAF.KnownBotReverseDNS`    | Google, Bing, Baidu, Apple crawler hostnames        | Comma-separated hostname patterns with `*` wildcards, e.g. `*.googlebot.com`. Only checked when the UA already matched a known bot pattern. Verified by forward DNS lookup by default. |
| `MCR.WAF.VerifyReverseDNS`      | `true`                                              | When `true`, a successful reverse DNS match is additionally confirmed by a forward DNS lookup (prevents DNS spoofing).   |

#### Extending the default path allow list

Use MyCoRe's property inheritance to extend the defaults without losing them:

```properties
MCR.WAF.AllowedPaths=%MCR.WAF.AllowedPaths%,/my-public-api/.*
```

#### Extending the known bot lists

The same inheritance pattern works for the bot properties:

```properties
MCR.WAF.KnownBotUserAgents=%MCR.WAF.KnownBotUserAgents%,MyCustomBot
MCR.WAF.KnownBotReverseDNS=%MCR.WAF.KnownBotReverseDNS%,*.mycustombot.example.com
```

### Browser Sub Resources

A page that is served without a `WAF-PASSED` cookie, for example because its path is on the allow list, makes the browser request sub resources such as stylesheets, scripts and images. Those requests cannot solve a Proof of Work challenge, so without this feature they would be redirected to the challenge page and the document would render broken.

Browsers announce the purpose of a request in the [`Sec-Fetch-Dest`](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest) header. A request bypasses the challenge only if **both** conditions hold:

1. The `Sec-Fetch-Dest` value is listed in `MCR.WAF.SubResource.AllowedDestinations`.
2. The request is **not** mapped to any servlet, meaning it is served as a static file by the container's default servlet (`HttpServletMapping` reports `MappingMatch.DEFAULT`), **or** its path matches one of the patterns in `MCR.WAF.SubResource.AllowedPaths`.

The second condition is required because `Sec-Fetch-Dest` is sent by the client and can be forged. It keeps dynamically generated content behind the challenge. In a standard MyCoRe application no servlet is mapped to `/`, so static files land on the default servlet, while `*.xml` (`MCRStaticXMLFileServlet`) and `*.xed` / `*.xhtml` (XEditor) keep an `EXTENSION` mapping match and therefore stay protected.

| Property                                   | Default                          | Description                                                                                                                                       |
|--------------------------------------------|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.SubResource.AllowedDestinations`  | `style,script,image,font,xslt`   | Comma-separated `Sec-Fetch-Dest` values (case-insensitive). An empty value disables the sub resource bypass entirely.                              |
| `MCR.WAF.SubResource.AllowedPaths`         | `/rsc/sass/.+`                   | Comma-separated Java regex patterns matched against the request path (without context path). Only evaluated when the `Sec-Fetch-Dest` value was accepted. |

`MCR.WAF.SubResource.AllowedPaths` covers sub resources that are delivered by a servlet instead of the default servlet, so the mapping check alone does not let them through. The default entry is the compiled CSS served by MyCoRe's JAX-RS resource `MCRSassResource`. Assets that the container itself serves from a JAR's `META-INF/resources`, WebJars for example, already pass via the mapping check and need no entry here. Extend the list via property inheritance:

```properties
MCR.WAF.SubResource.AllowedPaths=%MCR.WAF.SubResource.AllowedPaths%,/my-assets/.+
```

### Reverse DNS Cache

Reverse DNS lookups are expensive. Results are cached in a bounded `MCRCache`.

| Property                     | Default | Description                                                                   |
|------------------------------|---------|-------------------------------------------------------------------------------|
| `MCR.WAF.DNSCacheCapacity`   | `1000`  | Maximum number of IPs held in the cache (LRU eviction).                       |
| `MCR.WAF.DNSCacheTTLMinutes` | `60`    | How long a cached hostname is considered valid before the lookup is repeated. |

### Proof of Work Challenge

| Property                           | Default | Description                                                                                                                                                         |
|------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.Difficulty`               | `16`    | Number of leading zero bits required in the SHA-256 hash. 16 bits ≈ 1–5 seconds on a modern browser. Increase for stricter protection, decrease for weaker clients. |
| `MCR.WAF.MaxAttempts`              | `3`     | Number of failed challenge attempts allowed before the failure page is shown.                                                                                       |
| `MCR.WAF.ChallengeExpiryMinutes`   | `2`     | How long a generated challenge token is valid.                                                                                                                      |
| `MCR.WAF.PassedTokenExpiryMinutes` | `1440`  | How long the `WAF-PASSED` cookie is valid (1 day). After expiry the client must solve the challenge again.                                                          |

### Custom Templates

The challenge and failure pages can be replaced with custom HTML/JS files on the classpath.

| Property                    | Default                   | Description                                                        |
|-----------------------------|---------------------------|--------------------------------------------------------------------|
| `MCR.WAF.ChallengeHtml`     | `pow-challenge.html`      | Classpath path to the challenge page template.                     |
| `MCR.WAF.ChallengeFailHtml` | `pow-challenge-fail.html` | Classpath path to the failure page template.                       |
| `MCR.WAF.ChallengeScript`   | `pow-challenge.js`        | Classpath path to the JavaScript embedded into the challenge page. |

Templates use `{{key}}` placeholders. Keys are resolved first from explicitly passed values (e.g. `pow_challenge_token`), then from the MyCoRe i18n system (`MCRTranslation`). The built-in templates support English and German.

## Security notes

- **WAF-PASSED cookie:** The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` (when the application is served over HTTPS). It is a signed JWT bound to the client's IP address, so it cannot be reused from a different IP.
- **Challenge tokens:** Signed JWTs with a short expiry (default 2 minutes). They include the client IP, so a token captured by a third party cannot be used to pass the challenge.
- **Proof of Work:** The nonce submitted by the client is validated server-side using SHA-256. The difficulty is embedded in the signed token and cannot be tampered with by the client.
- **Reverse DNS spoofing:** When `MCR.WAF.VerifyReverseDNS=true` (the default), the plugin performs a forward DNS lookup to confirm that the resolved hostname actually points back to the original IP, preventing DNS spoofing attacks. Additionally, the DNS lookup is only triggered when the User-Agent already identifies the request as a known bot — arbitrary requests never incur a DNS lookup.
- **Sub resource bypass:** The `Sec-Fetch-Dest` header comes from the client and can be forged, so it is never sufficient on its own. A request also has to be unmapped (static file) or match `MCR.WAF.SubResource.AllowedPaths`. Note that a request to a non-existing path is unmapped as well, so 404 responses are reachable without solving a challenge.
- **Bot detection:** In addition to the PoW check, the plugin inspects the browser fingerprint submitted with the solution (User-Agent, WebDriver flag, screen resolution, language list, etc.) to reject obvious bots even if they manage to solve the hash challenge.

## License

GNU General Public License v3 — see [LICENSE.txt](LICENSE.txt).
