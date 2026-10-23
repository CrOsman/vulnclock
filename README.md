# VulnClock

Vulnerability handling for the EU Cyber Resilience Act (Regulation (EU) 2024/2847), for small software makers:

- **SBOM** in CycloneDX 1.5 JSON (Annex I, Part II, point 1) from `package-lock.json`, `composer.lock`, Android Gradle projects and iOS projects (CocoaPods, Swift Package Manager), merged into one when an app has several (Capacitor, React Native).
- **Known vulnerabilities** in every component from [OSV.dev](https://osv.dev), with CVSS, the fixed versions and a flag when the vulnerability is **exploited in the wild** ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [ENISA EUVD](https://euvd.enisa.europa.eu)), which is where the Article 14 reporting clock can start.
- **Daily monitoring** of the released version in GitHub Actions: one issue with the current findings, a comment on every new one, the `cra-24h` label when one is exploited.
- **Report helper** (`wizard/index.html`): the ENISA Single Reporting Platform fields for the 24 h early warning, 72 h notification and final report, with their limits, the deadlines and a user advisory draft. Runs offline; nothing leaves the page.

Requires Node.js 20 or later and has no dependencies. Made by 3D&TECH LAB d.o.o. (Croatia), Apache-2.0 licensed. Not legal advice: see [docs/CRA-NOTES.md](docs/CRA-NOTES.md) for what the Regulation says and [docs/RUNBOOK.md](docs/RUNBOOK.md) for what to do when something is exploited.

## Command line

```bash
git clone https://github.com/CrOsman/vulnclock.git
node vulnclock/bin/vulnclock.mjs check path/to/product --name "My Product" --version 1.4.0 --manufacturer "Example Ltd" --md cra-report.md
```

| Command | Does |
| --- | --- |
| `sbom [dir] --out sbom.cdx.json` | SBOM of the production dependencies. `--ship-dev a,b` adds dev dependencies that ship in the product (and what they depend on); `--include-dev` adds all; `--ecosystem npm,gradle,...` limits it to some of npm, composer, gradle, cocoapods, spm (default: all that are found) |
| `scan --sbom sbom.cdx.json --out cra-findings.json --md report.md` | Known vulnerabilities of any CycloneDX SBOM (also one made by [Syft](https://github.com/anchore/syft) for other ecosystems). `--fail-on exploited\|critical\|high\|medium\|low` exits 1 when something meets the bar |
| `check [dir]` | `sbom` and `scan` together; `--out` is the SBOM, `--findings` the result |
| `issue --findings cra-findings.json --repo owner/name` | Opens, updates or closes the monitoring issue (uses `gh`) |

## Android and iOS apps

Run it on the app folder; `android/` and `ios/App/` are found by themselves.

- **Android (Gradle, Groovy or Kotlin DSL):** the declared dependencies of every module in `settings.gradle`, including Capacitor and Cordova plugin modules in `node_modules`. Release configurations count (`implementation`, `api`, `runtimeOnly`, `release…`, flavours); test, debug, `compileOnly` and annotation processors do not. Versions come from `ext` variables (`variables.gradle`), `gradle.properties`, plugin defaults and `gradle/libs.versions.toml` (libraries and bundles). That is the top-level list the CRA asks for at the very least. With [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), the `gradle.lockfile` gives the full release runtime list and is used instead.
- **iOS, CocoaPods:** `Podfile.lock`. Without it, only pods with a fixed version are checked (local pods from `node_modules`, `'1.2.3'` pins); pods without a version or with a range (`'~> 11.0'`) are listed as not checked, so commit `Podfile.lock`. Your own local pods are your code, not dependencies, and are left out.
- **iOS, Swift Package Manager:** `Package.resolved`. Without it, the packages pinned with `exact:` in `Package.swift` (Capacitor 8 `CapApp-SPM`) or with an exact version in the Xcode project. Local path packages are npm packages and come from `package-lock.json`.
- A component without a known version is never matched against advisories (that would list every advisory the package ever had); the report names it under "Not checked (version unknown)".

No build runs, and nothing needs Gradle, Xcode or a Mac. For the full transitive list on Android, turn on dependency locking, or make an SBOM in the build (e.g. with the [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin)) and pass it to `scan`.

**What the vulnerability data covers.** OSV.dev has Maven, npm and Swift advisories, but no CocoaPods database. A pod from an npm package (Capacitor and its plugins) is checked as that npm package; any other pod is checked as its git repository in the Swift ecosystem of the GitHub Advisory Database, found through its podspec on the CocoaPods CDN. Pods whose repository has never had a Swift advisory there (older Objective-C pods are often only in NVD) show no findings even when NVD lists a CVE, and anything no database covers is named under "Not checked (no vulnerability database covers them)". React Native autolinked modules and Flutter plugins are added to the Android build at build time and are not read: VulnClock says so, and dependency locking or an SBOM from the build covers them.

## GitHub Actions

Copy [templates/workflows/vulnclock.yml](templates/workflows/vulnclock.yml) to `.github/workflows/vulnclock.yml` in the product repository and adjust its `with:` block. It checks every release tag and, every day, the latest release, attaches the SBOM to the release and keeps the `cra` issue up to date.

```yaml
- uses: CrOsman/vulnclock@v0
  with:
    product-name: My Product
    manufacturer: Example Ltd
    issue: 'true'          # needs permissions: issues: write
    fail-on: none          # or exploited / critical / high to fail the job
```

For an Electron app add `ship-dev: electron`: Electron is a devDependency, but it ships in every installer.

### Optional: VulnClock Pro dashboard

With `vulnclock-token: ${{ secrets.VULNCLOCK_TOKEN }}` each check is also uploaded to the [VulnClock Pro](https://app.vulnclock.com) dashboard: the Article 14 reporting clock per vulnerability, a decision log you cannot edit afterwards, and drafts for the ENISA Single Reporting Platform. The token is sent only in the Authorization header, the upload uses HTTPS, and a failed upload only warns. Without a token nothing leaves your CI, and the Action works as described above.

## Limits

- "Exploited in the wild" means listed in CISA KEV or with an exploitation date in ENISA EUVD. Whether it is exploited **in your product** is your decision; the reporting duty is about your product.
- A vulnerability database knows only published advisories. Your own code needs its own tests and reviews (Annex I, Part II, point 3).
- Standalone SaaS is reported to be out of the Regulation's scope under the Commission's draft guidance of March 2026 (secondary sources; check the final guidance); apps, desktop software and firmware placed on the EU market are in.

## Security and licence

Found a vulnerability in VulnClock itself? See [SECURITY.md](SECURITY.md). VulnClock is licensed under the [Apache License 2.0](LICENSE).
