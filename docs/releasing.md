# Releasing

## Datadog-opentelemetry

1. Bump libdatadog dependencies to their latest version. Unless there are specific reasons not to,
   we should make a fresh release of libdatadog crates just before dd-trace-rs releases to benefit
   from upgrades

2. Check the commits that are going in the new release, by creating a draft release in github
   <https://github.com/DataDog/dd-trace-rs/releases/new>

3. Append to the CHANGELOG.md, adding only additions/removal/fixes that affect customers

4. Check that the README and rustdocs are up to date with the current feature set and that they
   render correctly on github. rustdocs can be generated using the following command

```text
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc -p datadog-opentelemetry --no-deps
```

5. Merge all necessary modifications, then bump the crate version to the one you'd like to release.
   Grep and replace all occurrences of the current version number, as it is exposed also in
   documentation and in links to doc.rs

6. Merge the bump commit in `main`

7. Tag the bump commit with the release version. The tag should follow the following format:
   `datadog-opentelemetry-v0.0.0`, then push it to github.

```text
VERSION="0.0.0" # Placeholder, please replace!
BUMP_COMMIT_HASH="PUT THE HASH HERE" # Placeholder, please replace!
TAG="datadog-opentelemetry-v$VERSION"
git tag $TAG main -m "Release v$VERSION of datadog-opentelemetry"
echo "Tagged release $TAG"
```

> [!CAUTION]
> Pushing the tag to github will trigger the release automation. Run `git log`, and check that the
> tag name and tagged commit are correct before running the following command

```text
git push origin $TAG
```

8. Once the tag has been pushed, the publish job will need to be approved by another member of the
   apm-rust github group

9. Make a github release, from the previous release to the new tag.
   You can auto-generate the release notes.
   <https://github.com/DataDog/dd-trace-rs/releases/new>
