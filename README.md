## certonaut

[![CI](https://github.com/GermanCoding/certonaut/actions/workflows/rust.yml/badge.svg)](https://github.com/GermanCoding/certonaut/actions/workflows/rust.yml) [![Nightly Builds](https://img.shields.io/badge/nightly-latest-blueviolet)](https://nightly.link/certonaut/certonaut/workflows/rust/main) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Rust‑native ACME (RFC 8555) client and library for fully automated issuance, renewal, and management of X.509 certificates.
Supports HTTP-01 and DNS-01 challenges, in a fully guided interactive mode. Features a (Linux-only) eBPF “magic” solver to solve HTTP-01 challenges automatically.

<!--TODO: Asciicast video -->

---

## Table of Contents

- [Features](#features)
- [Documentation](#quick-start--documentation)
- [Developer Guide](#developer-guide)
- [Contributing](#contributing)
- [License](#license)

---

> [!WARNING]
> Certonaut is currently in alpha. While basic functionality is expected to work, no stability is currently guaranteed. Certonaut is not yet feature-complete.

## Features

- **eBPF "Magic" Solver**   
  A challenge solver for the ACME HTTP-01 challenge that works independently of any installed webserver.
  Can temporarily capture incoming HTTP connections to answer HTTP-01 challenges, acting as a temporary reverse-proxy
  for non-challenge requests. Does not require configuration.

- **Interactive mode**   
  Tired of having to learn yet another command line syntax? Annoyed to have to bring up the docs because you forgot how that
  command-line switch was called? Certonaut's interactive mode may be for you: The fully-guided interactive mode
  allows you to select most options in an interactive terminal prompt - no command line arguments required!

- **Non-interactive mode**   
  If the interactive mode isn't suitable for your use-case (e.g., scripts), certonaut also has an extensive command line.

- **ACME Account & CA Management**  
  Create, list, and remove ACME accounts and certificate authorities via CLI or interactive menu.

- **Certificate Issuance & Renewal**  
  Issue and renew certificates with custom key types (ECDSA, RSA up to 8192‑bit)

- **ARI support**  
  Full support for [ACME Renewal Information (ARI) extension](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/)

- **Profile support**  
  Full support for [ACME profiles extension](https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/)

- **Installer Hooks**  
  Run user‑provided scripts after issuance or renewal to install the fresh certificate as you prefer.

- **And several more...**

---

## Quick Start & Documentation

The user documentation for certonaut is @ https://docs.certonaut.net. Please refer to the guides there for installation and usage.

The rest of this documentation is meant for developers interested in certonaut.

---

## Developer Guide

### Code Layout

- **`src`** – Source Code (Rust, except for eBPF solver)
- **`tests`** – Integration tests
- **`testdata`** – All test resources required by tests
- **`db`** – Database-related files (migrations)
- **`.sqlx`** – Offline SQL query cache for [sqlx](https://github.com/launchbadge/sqlx/) compile-time SQL query checker.

### Local Development

- Follow installation instructions on [docs](https://docs.certonaut.net) page to setup dependencies
- `cargo test` to run the unit tests, `cargo test --all-features` to also run unit tests depending on features.
- `cargo test [--all-features] -- --ignored` to run the integration tests (currently Linux-only; Requires Docker)
- `cargo run [--all-features]` to run local code
- If you intend to make changes to any SQL query, you need to setup sqlx.
    - Install sqlx-cli as per [upstream instructions](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli). This usually boils down to a simple
      `cargo install sqlx-cli`.
    - Run `cargo run --bin create-dev-db` to create a development database with the current schema from `db/migrations`
        - If changes are made to the schema/migrations, re-run this command to re-create the development database
        - New migrations are currently created manually, because sqlx is not an ORM. If you add a new migration, follow the existing naming schema.
    - Set the environment variable
      `DATABASE_URL=sqlite://development.sqlite` to allow sqlx to find the development database.   
      This will allow the sqlx query checker to validate any new or changed SQL queries against the schema from the development database.
    - After you're done making changes to the schema and/or SQL queries, run
      `cargo sqlx prepare` to update the query cache in the .sqlx directory. Remember to commit any changes there.

---

## Contributing

1. **Fork** the repository and create a feature branch.
2. Run `cargo fmt` and `cargo clippy` to ensure style and lint compliance.
3. Add tests for any new functionality.
4. Submit a pull request against `main`.
5. Pull Requests will be squashed on merge, so feel free to add as many commits as you need.

---

## License

This project is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for full text.