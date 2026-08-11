# Contributing to apicore

Thank you for your interest in contributing.

## Requirements

- Node.js 24 LTS+
- pnpm 10+

## Setup

```bash
git clone https://github.com/technomoron/apicore.git
cd apicore
pnpm install
```

## Development

```bash
pnpm -r build      # build all packages
pnpm -r test       # run all tests
pnpm -r lint       # lint all packages
```

### Testing against MySQL and PostgreSQL

Tests run against SQLite by default. Point the Sequelize suites at a real server by
exporting connection URLs — there are no `.env` files, so pass them in the environment:

```bash
TEST_MYSQL_URL=mysql://root@localhost:3306/testdb \
TEST_PG_URL=postgres://user:pass@localhost:5432/testdb \
pnpm -r test
```

| Variable | Effect |
| --- | --- |
| `TEST_MYSQL_URL` / `TEST_PG_URL` | Connection URL. Unset means that dialect is skipped. |
| `TEST_SKIP_SQLITE` / `TEST_SKIP_MYSQL` / `TEST_SKIP_PG` | Skip a dialect even when its URL is set. |
| `TEST_REQUIRED_DIALECTS` | Comma-separated dialects the environment guarantees, e.g. `mysql,postgres`. A listed dialect that cannot be reached **fails** the run instead of skipping. CI sets this because it provisions both services. |

An unreachable dialect is skipped with a warning unless it is named in
`TEST_REQUIRED_DIALECTS`, so a machine with only SQLite still runs the suite clean.

Each package lives under `packages/`:

| Directory          | Package                       |
| ------------------ | ----------------------------- |
| `packages/server/` | `@technomoron/apicore-server` |
| `packages/client/` | `@technomoron/apicore-client` |

## Pull Requests

- Target the `main` branch.
- Include tests for new behaviour.
- Do not break existing tests.
- Keep changes focused — one concern per PR.
- Run `pnpm -r lint` and `pnpm -r test` locally before opening a PR.

The CI pipeline runs lint, build, and tests on Node 24.

## Reporting Issues

Use [GitHub Issues](https://github.com/technomoron/apicore/issues).
For security vulnerabilities, see [SECURITY.md](./SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under the MIT License.
