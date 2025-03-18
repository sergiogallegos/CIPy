## Contributing to CIPy

This document provides a brief guide on how to contribute to `CIPy`, a Python library for CIP and EtherNet/IP communication derived from `pycomm3`.

### Who Can Contribute?

Anyone is welcome to contribute! Contributions aren’t limited to code—filing bug reports, asking questions, adding examples, or improving documentation are all valuable ways to help. New users might find it easiest to start with documentation updates, type hinting, or test cases.

## Asking a Question

Questions can be posted as GitHub issues or discussions:
- **Discussions**: Best for general questions not tied to specific code or those that could benefit the community.
- **Issues**: Ideal for questions about features, potential feature requests, or bugs. Use the _Question_ template if submitting as an issue.

## Submitting an Issue

`CIPy` is a work in progress, and user-submitted issues help improve its quality. Before submitting, check existing issues to avoid duplicates.

### Bug Reports

To report a bug, create an issue using the _Bug Report_ template. Provide as much detail as possible to speed up resolution. Include:
- `CIPy` version (e.g., `pip show cipy`).
- Device details (model, firmware, etc.) if the bug is device-specific.
- Logs (see [documentation](https://cipy.readthedocs.io/en/latest/getting_started.html#logging) for setup).
  - Use `LOG_VERBOSE` level for maximum detail.
  - A helper method simplifies logging to a file.
- Sample code to reproduce the bug.

### Feature Requests

For new features or enhancements, use the _Feature Request_ template. Examples include:
- Adding missing features from similar libraries (e.g., "Library X has Y—can `CIPy` support it?").
- API changes (justify breaking changes with clear benefits).
- Enhancing existing features (e.g., more robust `EPATH` handling).
- Removing outdated or unsupported functionality.

## Submitting Changes

Code or documentation changes should be submitted as pull requests. Fork the repository, clone it locally, and work in the `develop` branch (the primary development branch). Pull requests should target `develop`. Once changes are tested and stable, they’ll be merged into `master` for a new release.

### Requirements for Contributions

To ensure quality, contributions must:
- Be _Pythonic_, adhering to PEP 8, PEP 20, and common conventions.
- Include docstrings for public methods (included in auto-generated docs).
- Use comments and docstrings to explain _why_ and _how_, not just _what_.
- Apply type hints to all public methods and as many internal ones as possible.
- Include tests for new functionality.
- Pass the _user_ tests (see Unit Testing in the README).
- Avoid third-party dependencies—use only the Python standard library.
- Minimize breaking changes unless well-justified.
- Avoid updating the library version (handled by maintainers).

### Suggested Contributions

- **Type Hinting**: Public methods are hinted, but many internal ones need work.
- **Tests**: Add offline tests or cover untested methods.
- **Examples**: Share scripts demonstrating `CIPy` features (e.g., using `EPATH` decoding).
  - Include your name/username/email in a comment/docstring for credit if desired.
- **Documentation**: Expand usage guides or clarify complex features like structs.

### New Feature or Example?

Deciding whether a change belongs in the library or as an example can be tricky. Features should be broadly applicable or require internal changes, while examples showcase existing functionality. If submitting an example, add credit details if you’d like recognition.

#### Examples of Feature vs. Example

- **[Feature] Full `EPATH` Decoding**:
  - Required internal changes to `data_types.py`.
  - Broadly applicable to CIP routing.
  - Enhances core functionality.

- **[Example] Reading Drive Parameters with `generic_message`**:
  - Uses existing `generic_message` method.
  - Specific to certain devices (e.g., PowerFlex drives).
  - Better as an external script than a core feature.

#### Questions to Ask
- Is this new functionality or a creative use of existing tools? (_New = feature, use = example_)
- Can it be done with current features? (_Yes = example_)
- Does it apply to most devices? (_Yes = feature_)
- Does it need internal changes? (_Yes = feature_)
- Is it useful? (_Must be for either_)
