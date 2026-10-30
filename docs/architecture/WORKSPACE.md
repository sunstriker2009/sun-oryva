# M0 Workspace Scaffold

Status: proposed scaffold, not functional authentication.

.NET 10 library projects: `Sun.Security.Abstractions` and `Sun.Security.AspNetCore`; future modules will be introduced as behavior requires. `tests/unit` contains a placeholder project, **not executable tests**. TypeScript uses pnpm workspace with an initial private `@sun-security/core` placeholder. No packages are published. CI currently checks .NET builds and TypeScript typecheck only; security tests, lint, dependency audits, and Keycloak integration tests are follow-up gates.

Local commands:

```sh
dotnet build src/backend/Sun.Security.AspNetCore/Sun.Security.AspNetCore.csproj
corepack enable
pnpm install
pnpm typecheck
```

Never treat the placeholder projects as production-ready or as authentication implementations.
