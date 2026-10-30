# ADR-001: Monorepo

**Status: Accepted (architecture baseline)**

Keep ORYVA-specific architecture, packages, design system, tests, infrastructure and CI together in `sun-oryva`. Keep SUN ecosystem repository limited to brand and portfolio governance. Require feature branches and PRs. Publish backend and frontend packages independently when useful. This favors coherent cross-stack changes at the cost of CI workspace management.
