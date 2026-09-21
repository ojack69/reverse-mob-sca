# reverse-mob-sca

Black-box Source Composition Analysis (SCA) for Android and iOS mobile applications. Given a list of third-party components reversed out of an app, it queries [Sonatype OSS Index](https://ossindex.sonatype.org/) for known CVEs affecting those components/versions.

> Note: this is a best-effort, black-box approach. It can produce false positives, especially when a component's version can't be determined reliably from the app bundle.

## How it works

| Platform | Input | Component identity | Source |
|---|---|---|---|
| Android | flat text file, one `group:artifact@version` per line | Maven PURL `pkg:maven/{group}/{artifact}@{version}` | `extract_packages_from_apk.py`, or [MobSF](https://mobsf.github.io/docs/) SBOM analysis |
| iOS | flat text file, one `name@version@bundle_identifier` per line | CocoaPods PURL `pkg:cocoapods/{name}@{version}` | `extract_packages_from_ipa.py` |

Both platforms are resolved through the same Sonatype OSS Index `component-report` API, which returns known vulnerabilities (CVE id, CVSS score, references) per component.

## Requirements

- Python >= 3.13
- [`uv`](https://docs.astral.sh/uv/)
- A free [Sonatype OSS Index](https://ossindex.sonatype.org/) account (username + API key)
    - Generate the API Key there: [Settings > User Tokens](https://guide.sonatype.com/settings/tokens)

## Setup

```bash
uv sync
export SONATYPE_USERNAME=<sonatype-username>
export SONATYPE_API_KEY=<sonatype-api-key>
```

## Usage

### Android

Two ways to produce the input file:

**Option A — `extract_packages_from_apk.py` (fast, no MobSF required)**

Reads build-system-embedded dependency metadata from the APK: `META-INF/<group>_<artifact>.version` files (written by AGP for every third-party dependency since it's also used by the Play Console SDK index — the dominant marker in modern release APKs) and `META-INF/maven/*/*/pom.properties` files (older Maven/Gradle publishing convention, less common in current Android builds). Best-effort: only dependencies that embed one of these markers are found (some builds strip `META-INF` entries via `packagingOptions`, or disable dependency metadata via `android.dependenciesInfo`), so coverage may be partial — fall back to Option B for a more complete (if manual) list.

```bash
uv run python extract_packages_from_apk.py /path/to/app.apk > android_components.txt
```

It also accepts an already-extracted APK directory instead of the raw `.apk` file.

**Option B — MobSF SBOM analysis**

1. Run MobSF against the target APK and export the SBOM.
2. Reduce it to a flat file of `group:artifact@version` lines, e.g.:

   ```
   com.squareup.okhttp3:okhttp@4.9.0
   com.google.guava:guava@31.1-jre
   ```

Then, either way, run:

```bash
uv run python main.py \
  -f android_components.txt \
  -o results.json \
  -p android
```

### iOS

1. Run the extraction helper (OS-independent — parses `Info.plist` files directly via `plistlib`/`zipfile`, no macOS `plutil` dependency) against the `.ipa` directly, or against an already-extracted app directory:

   ```bash
   uv run python extract_packages_from_ipa.py /path/to/App.ipa > ios_components.txt
   # or:
   uv run python extract_packages_from_ipa.py /path/to/Payload/App.app > ios_components.txt
   ```

2. Run:

   ```bash
   uv run python main.py \
     -f ios_components.txt \
     -o results.json \
     -p ios
   ```

## Options

| Flag | Required | Description |
|---|---|---|
| `-f`, `--file` | yes | Input file (format depends on `--platform`, see above) |
| `-o`, `--output` | yes | Path to write JSON results |
| `-p`, `--platform` | yes | `android` or `ios` |
| `--proxy` | no | Route requests through a proxy (e.g. `http://localhost:8080`) for interception/debugging; disables TLS certificate verification |
| `-v`, `--verbose` | no | Enable debug logging |

Sonatype credentials are read from environment variables, not flags:

| Variable | Required | Description |
|---|---|---|
| `SONATYPE_USERNAME` | yes | Sonatype OSS Index account username/email |
| `SONATYPE_API_KEY` | yes | Sonatype OSS Index API key |

## Output

`results.json` is a JSON array with one entry per resolved component:

```json
{
    "platform": "android",
    "name": "com.squareup.okhttp3:okhttp",
    "version": "4.9.0",
    "bundle_identifier": null,
    "description": "...",
    "reference": "https://ossindex.sonatype.org/component/...",
    "vulnerabilities": [
        {
            "cve": "CVE-2021-0341",
            "cvssScore": 5.9,
            "severity": "Medium",
            "references": ["https://...", "https://..."]
        }
    ]
}
```

`bundle_identifier` is only populated for `--platform ios` (taken from the input file); it's `null` for Android.

## Notes

- Requests are chunked (50 components per request) and throttled to respect Sonatype's rate limits; on `HTTP 429` the tool waits 30s and retries, up to 5 attempts per chunk before giving up on it.
- Malformed input lines are skipped with a warning rather than aborting the whole run.
