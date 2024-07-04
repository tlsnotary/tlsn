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

### Updating the changelog

Update the changes you have made in
[CHANGELOG](CHANGELOG.md)
file under the **Unreleased** section.

Add the changes of your pull request to one of the following subsections,
depending on the types of changes defined by
[Keep a changelog](https://keepachangelog.com/en/1.0.0/):

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

If the required subsection does not exist yet under **Unreleased**, create it!

## Style

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
