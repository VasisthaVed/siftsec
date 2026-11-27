# Git workflow

## Branches
- `main` is protected by the `protect-main` ruleset.
- One sub-phase = one branch: `feat/<phase>-<slug>`
  (e.g. `feat/10.4-prioritize`).
- No direct commits to `main`. Ever.

## Merging
- PRs are **squash-merged** (`allowed_merge_methods: ["squash"]`).
- Do not use `git merge --no-ff` on `main`; the ruleset blocks merge
  commits.
- PR title = the commit message that lands on `main`.
- Delete the branch after merge (the ruleset allows branch deletion
  for non-default branches; the default branch itself is
  deletion-protected).

## Linear history
The `required_linear_history` rule blocks any merge commit on `main`.
All PRs must be **squash-merged**. `git merge --no-ff` followed by
`git push origin feat/x:main` is blocked by the ruleset.

## Required checks
- `protect-main` requires the aggregate jobs listed in
  `.github/rulesets/main.json` (`quality-and-tests`).
- Check names must match the workflow job `name:` field verbatim.
- `integration_id: 15368` pins each check to the GitHub Actions app.

## Commits
- Conventional commits: `feat(10.4): ...`, `fix(10.3): ...`,
  `chore(github): ...`, `docs: ...`.
- DCO sign-off is required on every commit (`git commit -s`). If the
  DCO GitHub App is installed, add `dco` as a required status check;
  if not, note that DCO is enforced by review.

## Local hooks
- Hooks are local; the ruleset is the authority. `core.hooksPath` must
  be set by each contributor (`git config core.hooksPath .githooks`).

## Forbidden
- `git push --force` to `main`
- `git push --delete main`
- Direct commits to `main`
- Merge commits on `main`
