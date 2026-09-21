# reverse-mob-sca

Black-box Source Composition Analysis (SCA) for Android and iOS mobile applications. Given a list of third-party components reversed out of an app, it queries [Sonatype OSS Index](https://ossindex.sonatype.org/) for known CVEs affecting those components/versions.

> Note: this is a best-effort, black-box approach. It can produce false positives, especially when a component's version can't be determined reliably from the app bundle.

## How it works

| Platform | Input | Component identity | Source |
|---|---|---|---|
| Android | flat text file, one `group:artifact@version` per line | Maven PURL `pkg:maven/{group}/{artifact}@{version}` | [MobSF](https://mobsf.github.io/docs/) SBOM analysis |
| iOS | flat text file, one `name@version@bundle_identifier` per line | CocoaPods PURL `pkg:cocoapods/{name}@{version}` | `extract_packages_from_app_bundle.py` |

Both platforms are resolved through the same Sonatype OSS Index `component-report` API, which returns known vulnerabilities (CVE id, CVSS score, references) per component.

## Requirements

- Python >= 3.13
- [`uv`](https://docs.astral.sh/uv/)
- A free [Sonatype OSS Index](https://ossindex.sonatype.org/) account (username + API key)

## Setup

```bash
uv sync
```

## Usage

### Android

1. Run MobSF against the target APK and export the SBOM.
2. Reduce it to a flat file of `group:artifact@version` lines, e.g.:

   ```
   com.squareup.okhttp3:okhttp@4.9.0
   com.google.guava:guava@31.1-jre
   ```

3. Run:

   ```bash
   uv run python main.py \
     -f android_components.txt \
     -o results.json \
     -p android \
     --username <sonatype-username> \
     --api-key <sonatype-api-key>
   ```

### iOS

1. Extract the `.ipa`, then run the bundle extraction helper (OS-independent — parses `Info.plist` files directly via `plistlib`, no macOS `plutil` dependency) against the extracted app directory:

   ```bash
   uv run python extract_packages_from_app_bundle.py /path/to/Payload/App.app > ios_components.txt
   ```

2. Run:

   ```bash
   uv run python main.py \
     -f ios_components.txt \
     -o results.json \
     -p ios \
     --username <sonatype-username> \
     --api-key <sonatype-api-key>
   ```

## Options

| Flag | Required | Description |
|---|---|---|
| `-f`, `--file` | yes | Input file (format depends on `--platform`, see above) |
| `-o`, `--output` | yes | Path to write JSON results |
| `-p`, `--platform` | yes | `android` or `ios` |
| `--username` | yes | Sonatype OSS Index account username/email |
| `--api-key` | yes | Sonatype OSS Index API key |
| `--proxy` | no | Route requests through a proxy (e.g. `http://localhost:8080`) for interception/debugging; disables TLS certificate verification |
| `-v`, `--verbose` | no | Enable debug logging |

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
