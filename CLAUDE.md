This tool performs a "black-box" Source Composition Analysis for Android/iOS mobile applications by reversing their components and enumerating their versions. Note: this may introduce some false positives, specially when it's not possible to determine a component version reliably.

- main.py: Unified entrypoint for both platforms, queries the Sonatype OSS Index `component-report` API (requires a free API key) for known CVEs.
  - `--platform android`: expects a flat file of `group:artifact@version` lines obtained from MobSF SBOM analysis; queried as Maven PURLs (`pkg:maven/{group}/{artifact}@{version}`).
  - `--platform ios`: expects the output of `extract_packages_from_app_bundle.py` (`name@version@bundle_identifier` lines); queried as CocoaPods PURLs (`pkg:cocoapods/{name}@{version}`).
- extract_packages_from_app_bundle.py: OS-independent helper (uses `plistlib`, no macOS `plutil` dependency) that walks an extracted `.app`/`.ipa` bundle, reading `Info.plist` files to produce main.py's iOS input format. Replaces an earlier bash version that only worked on macOS.

Historical note: an earlier `android.py` scraped mvnrepository.com HTML pages directly; this was retired after Maven Central/mvnrepository added Cloudflare protection that blocks scraping, and its functionality was folded into main.py via Sonatype instead.
