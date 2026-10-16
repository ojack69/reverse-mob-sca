# reverse-mob-sca

Black-box Source Composition Analysis (SCA) for Android and iOS mobile applications. Given a list of third-party components reversed out of an app, it queries vulnerability databases ([Sonatype OSS Index](https://ossindex.sonatype.org/), [OSV.dev](https://osv.dev/)) for known CVEs affecting those components/versions — optionally including their child dependencies, resolved via [deps.dev](https://deps.dev/) (Android) or [CocoaPods Trunk](https://cocoapods.org/) podspecs (iOS).

> Note: this is a best-effort, black-box approach. It can produce false positives, especially when a component's version can't be determined reliably from the app bundle.

## How it works

| Platform | Component list format | Component identity | Source |
|---|---|---|---|
| Android | one `group:artifact@version` per line | Maven PURL `pkg:maven/{group}/{artifact}@{version}` | extracted from the `.apk` (`-a`), or [MobSF](https://mobsf.github.io/docs/) SBOM analysis (`-f`) |
| iOS | one `name@version[@bundle_identifier]` per line | CocoaPods PURL `pkg:cocoapods/{name}@{version}` | extracted from the `.ipa` (`-a`) |

Pipeline: extract (`-a`) or load (`-f`) components → validate → optionally expand with child dependencies (`-t`) → query advisory sources (`-s`) → merge into one record per component.

### Sources

| Source | Role | Platforms | Auth |
|---|---|---|---|
| [Sonatype OSS Index](https://ossindex.sonatype.org/) `component-report` | advisories | Android, iOS | free account (env vars) |
| [OSV.dev](https://osv.dev/) `querybatch` + `vulns/{id}` | advisories (Maven data from the GitHub Advisory Database) | Android | none |
| [deps.dev](https://deps.dev/) `:dependencies` | transitive dependency resolution (`-t`) | Android | none |
| [CocoaPods Trunk](https://cocoapods.org/) podspecs (`cdn.cocoapods.org/Specs/...`) | direct dependency declarations (`-t`) | iOS | none |

OSV has no CocoaPods ecosystem, so iOS advisories are Sonatype-only (unsupported sources are ignored with a warning). Findings from different sources are deduplicated by CVE id (or alias overlap, e.g. a GHSA id), and each vulnerability lists the `sources` that reported it. When sources disagree on the CVSS score, the first source in `-s` order wins; OSV scores are computed from the advisory's CVSS v3/v4 vector, falling back to the GHSA qualitative severity when no vector is available.

### Child dependencies (`-t`)

Similar to mvnrepository's "vulnerabilities from dependencies". Each component records its `relation` (`observed` in the app, or `direct`/`indirect` dependency) and `via` (the component(s) pulling it in), and gets a `dependency_vulnerabilities` rollup of its vulnerable descendants.

**Android** — for each observed component, deps.dev's resolved dependency graph is fetched, and every child (direct or indirect) is added to the components checked.

> Child versions are taken **as declared** in the upstream graph, not observed in the app: Gradle conflict resolution may ship a different (usually newer) version, and R8 may strip unused code entirely. Treat `direct`/`indirect` findings as lower-confidence leads and confirm the shipped version (e.g. against the APK's `META-INF/*.version` files or the decompiled code). Artifacts unknown to deps.dev are skipped with a warning.

**iOS** — for each observed pod, its podspec (at the observed version) is fetched from CocoaPods Trunk and its declared dependencies (root spec + default subspecs + subspecs requested by other pods) are read. Podspecs only declare version **constraints** (e.g. `FirebaseCore ~> 10.5`); the exact versions live in the app's `Podfile.lock`, which isn't shipped. So:

- a child **also observed** in the app (its own framework `Info.plist`) keeps its observed version, gets `via` and `requirements` (`{parent: [constraints]}`), and is checked against the constraints: mismatches are logged and listed in `constraint_violations` (usually a misread plist version or a vendored fork). Its own podspec is then followed too;
- a child **not observed** — typically statically linked, so no `Info.plist` of its own — is reported with `"resolved": false`, `"version": null` and its `requirements`, and is **not** queried (no version to check, and no podspec to follow).

Observed frameworks that aren't on CocoaPods Trunk (the app itself, SPM/vendored libraries, or a plist version differing from the pod version) are skipped. A framework's `CFBundleName` doesn't always match its pod name; known cases (e.g. `FBLPromises` → `PromisesObjC`) are mapped in `cocoapods.FRAMEWORK_TO_POD`.

Only children are resolved: parent POMs carry no code, and reverse dependencies (who depends on a library) don't affect the app's exposure.

Code layout (`src/reverse_mob_sca/`): `cli.py` (argparse, orchestration, merging), `extract.py`, `validate.py`, `depsdev.py`, `cocoapods.py`, `sources/{sonatype,osv}.py`, `severity.py`, `net.py`.

Extraction (`-a`) accepts a raw `.apk`/`.ipa` or an already-extracted APK/app bundle directory, and is OS-independent (`zipfile`/`plistlib`, no macOS `plutil` dependency):

- **Android** — reads build-system-embedded dependency metadata: `META-INF/<group>_<artifact>.version` files (written by AGP for every third-party dependency since it's also used by the Play Console SDK index — the dominant marker in modern release APKs) and `META-INF/maven/*/*/pom.properties` files (older Maven/Gradle publishing convention, less common in current Android builds). Best-effort: only dependencies that embed one of these markers are found (some builds strip `META-INF` entries via `packagingOptions`, or disable dependency metadata via `android.dependenciesInfo`), so coverage may be partial — fall back to a MobSF SBOM-derived list (`-f`) for a more complete (if manual) list.
- **iOS** — reads `CFBundleName`/`CFBundleShortVersionString`/`CFBundleIdentifier` from every embedded `Info.plist`.

### Input validation

Before any request is sent to any source, every entry (extracted or read from `-f`) is checked against the expected format for the platform. Entries containing whitespace, PURL delimiters (`/`, `?`, `#`), extra `@`/`:` separators, or otherwise not matching are rejected with a warning (reporting source and line number) and excluded from the query; children returned by deps.dev go through the same check. The run aborts if no valid entries remain.

| Platform | Accepted format |
|---|---|
| Android | `group:artifact@version` — group/artifact `[A-Za-z0-9][A-Za-z0-9._-]*` |
| iOS | `name@version[@bundle_identifier]` — name `[A-Za-z0-9][A-Za-z0-9._+-]*`, bundle id `[A-Za-z0-9._-]*` |

Versions must match `[A-Za-z0-9][A-Za-z0-9._+~-]*`. Note that an iOS app's own `Info.plist` often has a `CFBundleName` with spaces (e.g. `My App`): it is rejected by design, as it's not a third-party component anyway.

## Requirements

- Python >= 3.13
- [`uv`](https://docs.astral.sh/uv/)
- A free [Sonatype OSS Index](https://ossindex.sonatype.org/) account (username + API key), unless you only use `-s osv`
    - Generate the API Key there: [Settings > User Tokens](https://guide.sonatype.com/settings/tokens)

## Setup

Either run from a checkout with `uv`:

```bash
uv sync
uv run reverse-mob-sca -h
```

or install it as a standalone CLI (isolated venv, `reverse-mob-sca` on `PATH`):

```bash
pipx install .                 # from a local checkout
pipx install git+<repo-url>    # or straight from the repository
# equivalently: uv tool install .
```

Then set the Sonatype credentials (only needed when `sonatype` is among `--sources`):

```bash
export SONATYPE_USERNAME=<sonatype-username>
export SONATYPE_API_KEY=<sonatype-api-key>
```

## Usage

Examples use `uv run reverse-mob-sca`; drop the `uv run` prefix when installed via `pipx`/`uv tool`.

Scan an app directly (extract + validate + query):

```bash
uv run reverse-mob-sca -p android -a /path/to/app.apk -o results.json
uv run reverse-mob-sca -p ios -a /path/to/App.ipa -o results.json
# extracted directories work too:
uv run reverse-mob-sca -p ios -a /path/to/Payload/App.app -o results.json
```

Also checking child dependencies — Android, OSV only (no Sonatype account needed); iOS (CocoaPods Trunk podspecs):

```bash
uv run reverse-mob-sca -p android -a /path/to/app.apk -t -s osv -o results.json
uv run reverse-mob-sca -p ios -a /path/to/App.ipa -t -o results.json
```

Extract only, to review/edit the component list before querying (no advisory source is queried, so no Sonatype credentials needed; writes to stdout unless `-o` is given):

```bash
uv run reverse-mob-sca -p android -a /path/to/app.apk --extract-only > android_components.txt
# include resolved children too (validated, same format; iOS unresolved children are only logged):
uv run reverse-mob-sca -p android -a /path/to/app.apk --extract-only -t > android_components.txt
```

Scan a pre-built component list (e.g. from `--extract-only`, or a MobSF SBOM reduced to `group:artifact@version` lines):

```
com.squareup.okhttp3:okhttp@4.9.0
com.google.guava:guava@31.1-jre
```

```bash
uv run reverse-mob-sca -p android -f android_components.txt -o results.json
```

## Options

| Flag | Required | Description |
|---|---|---|
| `-p`, `--platform` | yes | `android` or `ios` |
| `-a`, `--app` | one of `-a`/`-f` | Raw `.apk`/`.ipa` or extracted app directory to extract components from |
| `-f`, `--file` | one of `-a`/`-f` | Pre-built component list (format depends on `--platform`, see above) |
| `-o`, `--output` | yes, unless `--extract-only` | Path to write JSON results; with `--extract-only`, path to write the component list (default: stdout) |
| `-s`, `--sources` | no | Comma-separated advisory sources: `sonatype`, `osv` (default: both; iOS: `sonatype` only) |
| `-t`, `--transitive` | no | Also resolve child dependencies: deps.dev on Android (versions as declared upstream), CocoaPods Trunk podspecs on iOS (constraints only; see above) |
| `--extract-only` | no | Only extract the component list from `-a` (plus children with `-t`) and write it out, without querying advisory sources |
| `--proxy` | no | Route requests through a proxy (e.g. `http://localhost:8080`) for interception/debugging; disables TLS certificate verification |
| `-v`, `--verbose` | no | Enable debug logging |

Sonatype credentials are read from environment variables, not flags (only needed when `sonatype` is among `--sources`, and never with `--extract-only`):

| Variable | Required | Description |
|---|---|---|
| `SONATYPE_USERNAME` | with `-s sonatype` | Sonatype OSS Index account username/email |
| `SONATYPE_API_KEY` | with `-s sonatype` | Sonatype OSS Index API key |

## Output

`results.json` is a JSON array with one entry per checked component:

```json
{
    "platform": "android",
    "name": "com.squareup.okhttp3:okhttp",
    "version": "4.9.0",
    "bundle_identifier": null,
    "resolved": true,
    "relation": "observed",
    "via": [],
    "sources": ["sonatype", "osv"],
    "description": "...",
    "reference": "https://ossindex.sonatype.org/component/...",
    "vulnerabilities": [
        {
            "cve": "CVE-2021-0341",
            "aliases": ["GHSA-3cqm-mf7h-prrj"],
            "cvssScore": 7.5,
            "severity": "High",
            "references": ["https://...", "https://..."],
            "sources": ["osv", "sonatype"]
        }
    ],
    "dependency_vulnerabilities": [
        {"name": "org.jetbrains.kotlin:kotlin-stdlib", "version": "1.4.10", "ids": ["CVE-2022-24329", "CVE-2020-29582"]}
    ]
}
```

- `resolved`: `false` only for iOS declared-but-unobserved children (`version` is `null`, nothing queried).
- `requirements` / `constraint_violations` (iOS only): declared version constraints per parent, and observed versions not satisfying them.
- `relation`: `observed` (found in the app / input list), or `direct`/`indirect` (pulled in via `-t`); `via` lists the observed component(s) it was resolved from.
- `sources`: which sources returned a result for the component (empty if every source failed for it).
- `cve`: the CVE id when one exists, otherwise the source's own id (e.g. a GHSA id); other ids are in `aliases`.
- `dependency_vulnerabilities`: vulnerable descendants of the component (only populated with `-t`).

`bundle_identifier` is only populated for `--platform ios` (taken from the extracted `Info.plist` or the input file; `null` if absent); it's always `null` for Android.

## Notes

- Sonatype requests are chunked (50 components per request) and throttled to respect Sonatype's rate limits; on `HTTP 429` the tool waits 30s and retries, up to 5 attempts per chunk before giving up on it. OSV queries are batched (up to 1000 per request); deps.dev is queried once per observed component, CocoaPods Trunk once per observed pod.
- Malformed input entries are rejected upfront (see [Input validation](#input-validation)) with a warning rather than aborting the whole run.
