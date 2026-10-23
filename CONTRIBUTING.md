# Contributing

Thank you for helping. Bug reports, documentation fixes and pull requests are welcome.

## Before you start

- **Security problems** go to security@qertum.com, not to a public issue. See [SECURITY.md](SECURITY.md).
- For anything larger than a small fix, open an issue first and describe the problem you want to solve, so we can agree on the approach before you spend time on it.
- Qertum is a certificate authority. Changes that touch key handling, authentication, authorisation, the audit trail or issuance policy are reviewed more strictly and must come with tests.

## Building and testing

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download) and Docker.

```bash
dotnet build Qertum.sln
dotnet test Qertum.sln
```

The integration tests (`IT-*`) and the identity-provider interop tests start containers and fail when no Docker daemon is running; that is not a regression. To run the whole stack from source, see the [Local Development](https://github.com/Qertum/qertum/wiki/Local-Development) page of the wiki.

## Pull requests

- Keep a pull request to one change, with a description of what it does and why.
- Add or update tests, and run the whole suite before you submit.
- Match the surrounding code: naming, comment density and idiom. Public members need XML documentation.
- Package versions live only in `Directory.Packages.props`.
- Update the user-facing text a change affects (the interface copy, `qca` help and the README or wiki page that describes it).

## Sign-off

Every commit must carry a `Signed-off-by` line, which certifies that you wrote the change or have the right to submit it under the project's MIT licence ([Developer Certificate of Origin 1.1](https://developercertificate.org/)). Add it with `git commit -s`.

## What happens to an accepted change

The maintainers develop in a private repository, and this repository receives one snapshot commit per release. An accepted pull request is applied there, with you credited as author, and appears here with the next release.

## Conduct

Be respectful. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
