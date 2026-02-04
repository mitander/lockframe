# lockframe

[![CI](https://github.com/mitander/lockframe/actions/workflows/ci.yml/badge.svg)](https://github.com/mitander/lockframe/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/mitander/lockframe/branch/master/graph/badge.svg)](https://codecov.io/gh/mitander/lockframe)

A high-assurance messaging protocol combining **End-to-End Encryption** with **Server-Side Moderation**.

Built on [MLS](https://www.rfc-editor.org/rfc/rfc9420.pdf) and [QUIC](https://www.rfc-editor.org/rfc/rfc9000.pdf) which allows servers to cryptographically enforce bans, ordering, and group membership without accessing message content.

## Design

- **Hub-Centric:** Servers enforce total ordering and moderation via MLS External Commits.
- **Action-Based:** Protocol logic returns actions for the driver to execute, keeping it pure and testable.
- **Zero-Copy:** Wire format designed for O(1) routing.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol Specification](docs/PROTOCOL.md)
- [Roadmap](docs/ROADMAP.md)

## License

[Apache 2.0](LICENSE)
