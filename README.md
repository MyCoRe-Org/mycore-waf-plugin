# MyCoRe WAF Plugin

A Web Application Firewall (WAF) plugin for [MyCoRe](https://www.mycore.de/) applications. It protects against bot attacks by issuing a **Proof of Work (PoW)** challenge that must be solved in the browser before any request is served. Legitimate search engine crawlers are let through via an allow list based on IP ranges, paths, or verified reverse DNS lookups (only triggered when the User-Agent identifies a known bot).

## How it works

1. An incoming request hits the `WAFFilter`, which is automatically registered for all URLs (`/*`) on startup.
2. The filter checks allow lists in order: path → IP range → XML allow rules → browser sub resource → valid `WAF-PASSED` cookie → known bot reverse DNS. Matching requests pass through immediately.
3. For the reverse DNS check, the User-Agent is inspected first. Only if it matches a known bot pattern (e.g. `Googlebot`, `bingbot`) is the expensive DNS lookup performed and the resolved hostname verified.
4. If no allow list matches, the client is redirected to the PoW challenge page.
5. The browser solves the SHA-256 PoW challenge in JavaScript and submits the solution.
6. The server validates the solution and checks the submitted browser fingerprint against the suspicion rules. If no rule matches, it sets the `WAF-PASSED` cookie and redirects the client to the originally requested URL.
7. If a suspicion rule matches, the client has to click a checkbox that is drawn on a canvas at a random position (interaction challenge). The recorded events are validated by the server before the cookie is set.
8. After too many failed attempts the client is shown a failure page.

```
Request
  │
  ├─ Path allow list match?              ──yes──> pass through
  ├─ IP allow list match?                ──yes──> pass through
  ├─ XML allow rule match?               ──yes──> pass through
  ├─ Allowed browser sub resource?       ──yes──> pass through
  ├─ Valid WAF-PASSED cookie?            ──yes──> pass through
  ├─ Known bot UA + reverse DNS match?   ──yes──> pass through
  ├─ Interaction result submitted?       ──yes──> validate events → set cookie → redirect to original URL
  ├─ Challenge solution submitted?       ──yes──> validate → suspicious? ──yes──> serve interaction challenge
  │                                                             └──no───> set cookie → redirect to original URL
  ├─ Challenge page requested?           ──yes──> serve PoW challenge page
  └─ (anything else)                     ──────> redirect to challenge page
```

## Installation

Add the JAR to the lib directory of your MyCoRe application. 
The JAR is self contained: the only library that MyCoRe does not provide, the [MaxMind DB Reader](https://github.com/maxmind/MaxMind-DB-Reader-java) (Apache License 2.0), is included and relocated to `org.mycore.waf.shaded` by the Maven Shade Plugin, so it cannot conflict with another version on the classpath. All other dependencies are `provided`.
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

### XML Allow Rules

For fine grained control the allow lists can be extended with XML rule files, parsed with JAXB. Each file contains a root `allow-list` element with any number of `rule` elements. A rule holds exactly one fact element, which may be a combinator (`and`, `or`, `not`) that contains further facts. A request passes the WAF without further checks if any rule of any configured file matches. The XML rules coexist with the properties above: path, IP, sub resource, cookie and reverse DNS allow lists keep working unchanged.

| Property                | Default  | Description                                                                                         |
|-------------------------|----------|-----------------------------------------------------------------------------------------------------|
| `MCR.WAF.AllowedRules`  | _(none)_ | Comma separated list of classpath resources with allow rule files, for example `waf/allow-list.xml`. |

Example that allows `GET /sru?style=xml` but rejects `?style=xml&style=json` and `?style=xml&foo=bar`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<allow-list xmlns="http://www.mycore.org/waf">
  <rule name="sru-style-xml">
    <and>
      <method value="GET"/>
      <path pattern="/sru"/>
      <parameter name="style" pattern="xml" unique="true" sole="true"/>
    </and>
  </rule>
</allow-list>
```

Available facts:

| Element           | Attributes                       | True if                                                                                                                              |
|-------------------|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `and`             |                                  | all child facts are true, fails closed if empty                                                                                       |
| `or`              |                                  | at least one child fact is true                                                                                                      |
| `not`             |                                  | the single child fact is false, fails closed if empty                                                                                |
| `method`          | `value`                         | the HTTP method is in the comma separated list, ignoring case                                                                        |
| `path`            | `pattern`                       | the regex fully matches the path relative to the application base URL, like `MCR.WAF.AllowedPaths`                                    |
| `parameter`       | `name`, `pattern`, `unique`, `sole` | a request parameter matches, see below                                                                                              |
| `parameter-count` | `value`, `min`, `max`, `mode`    | the number of request parameters matches, all constraints are combined                                                               |
| `header`          | `name`, `pattern`               | the header value fully matches the regex, the header name is looked up ignoring case                                                  |
| `user-agent`      | `pattern`                       | shortcut for `<header name="User-Agent" pattern="..."/>`                                                                              |
| `remote-address`  | `cidr` or `pattern`             | the client IP (honoring trusted proxies) lies in the CIDR range or fully matches the regex, `cidr` takes precedence                   |
| `cookie`          | `name`, `pattern`               | a cookie with the name exists, optionally with a value fully matching the regex                                                       |
| `content-type`    | `pattern`                       | the content type of the request fully matches the regex, false if the request has none                                                |
| `query-string`    | `pattern`                       | the raw query string fully matches the regex, false if the request has none                                                           |

The `parameter` fact offers two constraints beyond a plain value check:

- `unique="true"`: the parameter name occurs exactly once in the whole request, so `?style=xml` is accepted while `?style=xml&style=json` is rejected.
- `sole="true"`: no other parameter name exists in the request, so `?style=xml` is accepted while `?style=xml&foo=bar` is rejected.

The `parameter` fact is true if a parameter with the given name exists when `pattern` is omitted. The `parameter-count` fact counts distinct parameter names by default, with `mode="values"` it counts the total number of parameter occurrences.

All regexes are matched with `Matcher.matches()`, so the whole value has to match, not just a part of it. Rule files are validated against the packaged schema and checked for semantic errors before they are activated. Files that cannot be found, parsed or validated are logged as errors and skipped, requests then have to solve the challenge.

#### XML Schema

The XML schema for the rule files is generated from the JAXB model during the build and is packaged as `waf/allow-list.xsd` inside the JAR. Extract it and reference it to get validation and auto completion in XML editors:

```xml
<allow-list xmlns="http://www.mycore.org/waf"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="http://www.mycore.org/waf allow-list.xsd">
  ...
</allow-list>
```

The schema enforces that every `rule` contains exactly one fact element. Constraints that cannot be expressed in the schema are checked while loading. This includes nonempty combinators, valid regular expressions and consistent, nonnegative `parameter-count` constraints.

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

Reverse DNS lookups are expensive. Results are cached in a bounded `MCRCache`. Failed lookups (no reverse DNS entry, failed forward verification) are cached as well, so a client that fakes a known bot User-Agent triggers at most one lookup per IP and TTL. Concurrent requests from the same IP share a single lookup.

| Property                     | Default | Description                                                                   |
|------------------------------|---------|-------------------------------------------------------------------------------|
| `MCR.WAF.DNSCacheCapacity`   | `1000`  | Maximum number of IPs held in the cache (LRU eviction).                       |
| `MCR.WAF.DNSCacheTTLMinutes` | `60`    | How long a cached result (hostname or failed lookup) is considered valid before the lookup is repeated. |

### Proof of Work Challenge

| Property                           | Default | Description                                                                                                                                                         |
|------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.Difficulty`               | `16`    | Number of leading zero bits required in the SHA-256 hash. 16 bits ≈ 1–5 seconds on a modern browser. Increase for stricter protection, decrease for weaker clients. |
| `MCR.WAF.MaxAttempts`              | `3`     | Number of failed challenge attempts allowed before the failure page is shown.                                                                                       |
| `MCR.WAF.ChallengeExpiryMinutes`   | `2`     | How long a generated challenge token is valid.                                                                                                                      |
| `MCR.WAF.PassedTokenExpiryMinutes` | `1440`  | How long the `WAF-PASSED` cookie is valid (1 day). After expiry the client must solve the challenge again.                                                          |

### Suspicion Rules and Interaction Challenge

Some bots run real browsers and solve the Proof of Work challenge. Their fingerprints often still give them away, for example a server CPU with 192 cores, a screen resolution of `1280x1024`, a Chinese timezone combined with only English languages, or a Windows User-Agent on a Linux platform. After a valid solution the fingerprint is checked against XML suspicion rules. If any rule matches, the client gets no `WAF-PASSED` cookie yet. Instead it has to click a checkbox that is drawn on a canvas at a random position, so it cannot be found in the DOM.

The page records the events that lead to the click (pointer moves, pointer down/up, click, touch, key, focus and visibility events, each with timestamp, coordinates and `isTrusted`). The server accepts the interaction only if a trusted click hits the checkbox, it happened at least `MCR.WAF.Interaction.MinDurationMillis` after the page was shown, and a mouse click was preceded by at least `MCR.WAF.Interaction.MinPointerMoves` pointer moves. A failed interaction counts as a failed attempt and leads back to the Proof of Work challenge.

The outcome is logged at `INFO` together with the matching rule names. The complete recorded events are logged at `DEBUG` by `org.mycore.waf.WAFFilter`, so that bots that learn to pass the interaction challenge can be analyzed.

| Property                               | Default                             | Description                                                                                                  |
|----------------------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.SuspicionRules`               | `waf/default-suspicion-rules.xml`   | Comma separated list of classpath resources with suspicion rule files. An empty value disables the feature. |
| `MCR.WAF.Interaction.ExpiryMinutes`    | `5`                                 | How long the interaction token (and thus the checkbox) is valid.                                             |
| `MCR.WAF.Interaction.MinDurationMillis`| `600`                               | Minimal time between showing the checkbox and the click.                                                    |
| `MCR.WAF.Interaction.MinPointerMoves`  | `3`                                 | Minimal number of pointer moves before a mouse click. Touch and pen input is exempt.                        |

A suspicion rule file is validated against `waf/suspicion-list.xsd`, which is generated from the JAXB model and packaged in the JAR. Every `rule` needs a `name`, which is logged as the reason, and contains exactly one fact:

| Element                    | Attributes                         | Matches if                                                                                                                                 |
|----------------------------|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `and`, `or`, `not`         |                                    | all, any or none of the contained facts match                                                                                              |
| `value`                    | `field`, `pattern`, `match`        | the regex matches the whole value of a client information field. Array fields like `languages` match if any element matches (`match="all"`: every element) |
| `missing`                  | `field`                            | the field is missing, `null`, an empty string or an empty array                                                                            |
| `number`                   | `field`, `min`, `max`              | the numeric field lies in the inclusive range                                                                                              |
| `count`                    | `field`, `min`, `max`              | the number of array elements lies in the inclusive range                                                                                   |
| `header`                   | `name`, `pattern`, `match`         | the regex matches a header of the solution request (missing header never matches)                                                          |
| `same-as-header`           | `field`, `header`                  | the field equals the header, for example `userAgent` and `User-Agent`                                                                      |
| `timezone-offset-mismatch` |                                    | `timezone` is no known IANA timezone or does not fit `timezoneOffset` at `timestamp`                                                       |
| `remote-address`           | `cidr`, `pattern`                  | the client IP lies in one of the comma separated CIDR ranges and/or matches the regex                                                      |
| `country`                  | `code`, `database`                 | the regex matches the ISO country code of the client IP, see [GeoIP Databases](#geoip-databases)                                          |
| `asn`                      | `number`, `organization`, `database` | the regexes match the number and/or the organization of the autonomous system (network operator) of the client IP                       |
| `redirect-url`             | `pattern`, `match`                 | the regex matches the originally requested URL (relative to the base URL, with query string)                                              |

The client information fields are `userAgent`, `language`, `languages`, `platform`, `hardwareConcurrency`, `deviceMemory`, `screenResolution`, `colorDepth`, `timezone`, `timezoneOffset`, `plugins`, `webdriver`, `headless`, `cookieEnabled`, `doNotTrack`, `touchSupport` and `timestamp`.

```xml
<suspicion-list xmlns="http://www.mycore.org/waf/suspicion">
  <rule name="chinese-timezone-without-chinese-language">
    <and>
      <value field="timezone" pattern="Asia/(Shanghai|Chongqing|Harbin|Urumqi)"/>
      <not>
        <value field="languages" pattern="zh.*"/>
      </not>
    </and>
  </rule>
  <rule name="cloud-provider">
    <remote-address cidr="47.74.0.0/15, 8.208.0.0/12"/>
  </rule>
</suspicion-list>
```

If a fact cannot be evaluated because data is missing, for example a GeoIP fact for a private IP address or while the database has not been downloaded yet, the whole rule does not match, even if the fact is wrapped in `not`.

The default rules contain `outside-europe` (country not in the EU, the EEA, Switzerland, the United Kingdom, the micro states, the Western Balkans, Ukraine or Moldova) and `cloud-provider` (Amazon, Microsoft, Google Cloud, Oracle, Tencent, Alibaba, Huawei Cloud, DigitalOcean, Akamai/Linode and Vultr by AS number).

To keep the default rules and add your own, extend the property:

```properties
MCR.WAF.SuspicionRules=%MCR.WAF.SuspicionRules%,waf/my-suspicion-rules.xml
```

### GeoIP Databases

The `country` and `asn` facts look up the client IP in GeoIP databases in the MaxMind DB (MMDB) format. By default the databases `user-country.mmdb` and `origin-asn.mmdb` of [ip-location-db](https://github.com/sapics/ip-location-db) are used. They are published under the Public Domain Dedication and License (PDDL) and can be used without attribution. GeoLite2 and DB-IP MMDB files work as well, both the flat (`country_code`) and the nested (`country.iso_code`) country layout are supported.

The databases are stored in `MCR.WAF.GeoIP.Directory` and downloaded by a background thread at startup and every `MCR.WAF.GeoIP.UpdateIntervalHours` hours. With a checksum URL only the small SHA-256 file is fetched to check for changes, and every download is verified before it replaces the local file. A failed update keeps the previous database. Without URL only the local file is used, so a database can also be placed there manually, for example on servers without internet access (a proxy can be configured with the JVM properties `https.proxyHost` and `https.proxyPort`). The databases are only downloaded if suspicion rules are configured.

Private, loopback, link local, unique local (IPv6) and shared CGNAT addresses (`100.64.0.0/10`) are never looked up. GeoIP rules therefore never match local test systems or clients in a VPN with private addresses.

| Property                                     | Default                              | Description                                                                                |
|----------------------------------------------|--------------------------------------|--------------------------------------------------------------------------------------------|
| `MCR.WAF.GeoIP.Directory`                    | `%MCR.datadir%/waf/geoip`            | Directory of the database files. An empty value disables GeoIP.                            |
| `MCR.WAF.GeoIP.UpdateIntervalHours`          | `24`                                 | Interval between two update checks.                                                       |
| `MCR.WAF.GeoIP.Databases`                    | `country,asn`                        | Names of the databases, referenced by the `database` attribute of the facts.              |
| `MCR.WAF.GeoIP.Database.<name>.File`         | `user-country.mmdb`, `origin-asn.mmdb` | File name in the directory.                                                             |
| `MCR.WAF.GeoIP.Database.<name>.URL`          | ip-location-db release               | Download URL. Empty: only the local file is used.                                         |
| `MCR.WAF.GeoIP.Database.<name>.ChecksumURL`  | ip-location-db checksum release      | URL of the SHA-256 checksum (`sha256sum` format). Empty: download when the file is older than the update interval. |

### Custom Templates

The challenge and failure pages can be replaced with custom HTML/JS files on the classpath.

| Property                    | Default                   | Description                                                        |
|-----------------------------|---------------------------|--------------------------------------------------------------------|
| `MCR.WAF.ChallengeHtml`     | `pow-challenge.html`      | Classpath path to the challenge page template.                     |
| `MCR.WAF.ChallengeFailHtml` | `pow-challenge-fail.html` | Classpath path to the failure page template.                       |
| `MCR.WAF.ChallengeScript`   | `pow-challenge.js`        | Classpath path to the JavaScript embedded into the challenge page. |
| `MCR.WAF.InteractionHtml`   | `pow-interaction.html`    | Classpath path to the interaction challenge page template.         |
| `MCR.WAF.InteractionScript` | `pow-interaction.js`      | Classpath path to the JavaScript of the interaction challenge.     |

Templates use `{{key}}` placeholders. Keys are resolved first from explicitly passed values (e.g. `pow_challenge_token`), then from the MyCoRe i18n system (`MCRTranslation`). The built-in templates support English and German.

## Security notes

- **WAF-PASSED cookie:** The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` (when the application is served over HTTPS). It is a signed JWT bound to the client's IP address, so it cannot be reused from a different IP.
- **Challenge tokens:** Signed JWTs with a short expiry (default 2 minutes). They include the client IP, so a token captured by a third party cannot be used to pass the challenge.
- **Proof of Work:** The nonce submitted by the client is validated server-side using SHA-256. The difficulty is embedded in the signed token and cannot be tampered with by the client.
- **Reverse DNS spoofing:** When `MCR.WAF.VerifyReverseDNS=true` (the default), the plugin performs a forward DNS lookup to confirm that the resolved hostname actually points back to the original IP, preventing DNS spoofing attacks. Additionally, the DNS lookup is only triggered when the User-Agent already identifies the request as a known bot — arbitrary requests never incur a DNS lookup.
- **Sub resource bypass:** The `Sec-Fetch-Dest` header comes from the client and can be forged, so it is never sufficient on its own. A request also has to be unmapped (static file) or match `MCR.WAF.SubResource.AllowedPaths`. Note that a request to a non-existing path is unmapped as well, so 404 responses are reachable without solving a challenge.
- **Interaction challenge:** The interaction token is a signed JWT bound to the client IP that carries the checkbox position, so the client cannot move the checkbox. The checkbox only exists on a canvas. Synthetic events created by scripts have `isTrusted=false` and are rejected. Bots that control the browser via the DevTools protocol produce trusted events, which is why the events are logged for later analysis. The canvas checkbox cannot be operated with a keyboard or a screen reader, so it is only shown to clients that match a suspicion rule.
- **Bot detection:** In addition to the PoW check, the plugin inspects the browser fingerprint submitted with the solution (User-Agent, WebDriver flag, screen resolution, language list, etc.) to reject obvious bots even if they manage to solve the hash challenge.

## License

GNU General Public License v3 — see [LICENSE.txt](LICENSE.txt).
