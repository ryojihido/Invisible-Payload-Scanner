# Invisible Payload Scanner v0.5.0

v0.5.0 adds narrowly scoped protection for confirmed npm supply-chain incidents reported after the prior IOC baseline.

## Changes

- Adds a v0.5 rule pack for confirmed Keyv/Cacheable, AsyncAPI, Joyfill, Red Hat Miasma subset, and Alibaba-targeted campaign indicators.
- Adds exact package-version matching for manifests and lockfiles. Package names alone remain advisory-free unless they are part of a confirmed version rule.
- Adds targeted dependency-source scanning: with the normal `node_modules` setting, the scanner reads JavaScript only beneath package families named by the v0.5 rules, and reports a malicious-code finding only when a published high-specificity IOC is present.
- Covers both install-time (`preinstall`) and import-time payload delivery. This distinguishes incidents where `--ignore-scripts` would not prevent an implant from running when a module is loaded.
- Extends the self-test with Keyv, AsyncAPI, and Joyfill fixtures, including a check that targeted dependency source is inspected without enabling a full `node_modules` scan.

## Design boundary

This release does not label a package as dangerous from a namespace or a generic obfuscation term alone. It also does not claim that provenance, OIDC publishing, or a clean package name proves safety. It is a local, static pre-run check for documented evidence; it does not replace incident response, EDR, or a dependency-security service.
