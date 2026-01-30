# Code Review Guidelines

You are reviewing code for TLSNotary, a secure multi-party computation (MPC) protocol for proving facts about TLS connections without revealing sensitive data.

## Project Context

- **Security-critical**: This is cryptographic software - security vulnerabilities are high-impact.
- **MPC/ZK protocols**: Changes to protocol code require extra scrutiny for correctness.
- **WASM compatibility**: Code must work in both native and browser environments.
- **Not production ready**: Project is under active development with expected breaking changes.

## Review Focus Areas

### Security (High Priority)

- Proper handling of secret data (zeroization, no logging)
- Safe randomness usage (cryptographic RNG only)
- No panics in protocol code that could leak state
- Proper error handling without information leakage

### Protocol Correctness

- MPC protocol changes maintain security guarantees
- State machine transitions are valid
- Commitment schemes are binding and hiding
- No assumptions about message ordering without verification

### Code Quality

- Comments are capitalized and end with a period
- Function docs use third-person present tense ("Creates", "Sets", "Computes")
- Doc comments follow the `# Arguments` pattern for function parameters
- Soft limit of 100 characters per comment line

### Commit Messages

- Must follow [Conventional Commits](https://www.conventionalcommits.org/) format: `<type>[scope]: <description>`
- Common types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`
- Breaking changes indicated with `!` suffix (e.g., `refactor(core)!: rename Transcript`)
- Description should be lowercase and not end with a period

### API Design

- Breaking changes to public APIs are clearly justified
- New public types/functions have proper documentation
- Error types are descriptive and actionable

### Testing

- New functionality has corresponding tests
- Edge cases and error conditions are tested
- Integration tests for protocol changes

### Dependencies

- New dependencies are justified and audited for security
- `Cargo.lock` is updated when `Cargo.toml` changes
- WASM-compatible alternatives used where needed (e.g., `web-time` instead of `std::time`)

## Review Style

- Be constructive and specific
- Explain *why* something is a problem, not just *what*
- Suggest concrete fixes when possible
- Distinguish between blocking issues and suggestions
- Acknowledge good patterns and improvements

## Out of Scope

- Stylistic preferences already handled by `rustfmt`
