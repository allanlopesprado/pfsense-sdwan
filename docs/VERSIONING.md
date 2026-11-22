# Versioning and publishing

The project uses `MAJOR.MINOR.PATCH` version numbers and `vMAJOR.MINOR.PATCH` tags. The `0.x` series is experimental. Use a **patch** for compatible fixes and refinements, a **minor** version for new features that mark a project milestone, and a **major** version for a new series with compatibility changes. Compare all three components numerically. [Semantic Versioning](https://semver.org/)

## Release identity

| File or reference | Information |
| --- | --- |
| `Makefile` | The port version in `PORTVERSION`. |
| `dist/pfSense-pkg-SDWAN-<version>.pkg` and `.sha256` | The package and its checksum. |
| `dist/release.json` | The version, maturity, and SHA-256 that the WebGUI checks. |
| `docs/releases/v<version>.md` | The changes in English. The workflow uses this text to render the release notes. |
| GitHub tag | The tested revision that contains the package for that version. |

GitHub Releases distributes the latest version. The release index and notes identify the package as **experimental**. The **Updates** tab checks the published release and verifies that the asset's SHA-256 matches the index and the file at the release tag. [GitHub Releases](https://github.com/allanlopesprado/pfsense-sdwan/releases)

## Prepare a release

1. Update `PORTVERSION` in `Makefile`, add `docs/releases/v<version>.md`, and record the change in the [changelog](../CHANGELOG.md).
2. Push the source to `build/**` or run **Build pfSense package** in GitHub Actions against the packaging commit. The workflow builds twice and compares the bytes before uploading the build artifact.
3. Download the `sdwan-package` artifact, verify its checksum, and commit the `.pkg` and `.sha256` files in `dist/`. From that commit, generate the release index and README installation command.

   ```sh
   python3 tools/update-release-index.py --artifact-commit "$(git rev-parse HEAD)"
   python3 tools/update-release-index.py --check
   ```

4. Include the generated files in the publishing commit and use the subject `Release X.Y.Z` or `Release X.Y.Z <description>`. Push to `main`. The workflow checks the WebGUI, FreeBSD, IPsec, and the validation matrix, requires a version newer than published releases, then creates the tag and release.
5. After publication, verify the version, package, and SHA-256 on the release page. On an upgraded appliance, run [`verify-appliance.sh`](../tools/verify-appliance.sh) with the expected version.

The tag and assets identify the published package. To distribute a package change, increment the version and repeat the publishing process. For documentation and presentation changes, update the README or the GitHub release notes. [Managing releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)

[FreeBSD builds and lab validation](LAB.md)
