# Contribution guidelines

First off, thank you for contributing to `tlsn`.

If your contribution is not straightforward, please first discuss the change you
wish to make by creating a new issue.

## Reporting issues

Before reporting an issue on the
[issue tracker](https://github.com/tlsnotary/tlsn/issues),
please check that it has not already been reported by searching for some related
keywords.

## Pull requests

Try to do one pull request per change.

## Linting

Before a Pull Request (PR) can be merged, the Continuous Integration (CI) pipeline automatically lints all code using [Clippy](https://doc.rust-lang.org/stable/clippy/usage.html). To ensure your code is free of linting issues before creating a PR, run the following command:

```sh
cargo clippy --all-features --all-targets -- -D warnings
```

This command will lint your code with all features and targets enabled, and treat any warnings as errors, ensuring that your code meets the required standards.

## Style

This repository includes a `rustfmt.toml` file with custom formatting settings that are automatically validated by CI before any Pull Requests (PRs) can be merged. To ensure your code adheres to these standards, format your code using this configuration before submitting a PR. We strongly recommend enabling *auto format on save* to streamline this process. In Visual Studio Code (VSCode), you can enable this feature by turning on [`editor.formatOnSave`](https://code.visualstudio.com/docs/editor/codebasics#_formatting) in the settings.

### Capitalization and punctuation

Both line comments and doc comments must be capitalized. Each sentence must end with a period.

```
// This is a line comment.
```

### Avoid overly long comment lines

We recommend a soft comment line length limit of **100 characters**. Authors should aim to wrap lines before hitting this limit, but it is not a hard limit. Comments are allowed to exceed this limit.

### Verbs in function description

Comments describing a function usually start with a verb. That verb must use the third-person present tense, e.g. "Creates", "Sets", "Computes".

### Function arguments

Comments for function arguments must adhere to this pattern:

```
/// Performs a certain computation. Any other description of the function.
///
/// # Arguments
///
/// * `arg1` - The first argument.
/// * `arg2` - The second argument.
pub fn compute(...
```
