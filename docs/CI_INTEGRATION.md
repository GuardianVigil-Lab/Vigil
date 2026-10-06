# CI/CD Integration Runbook

Integrate Vigil into your deployment pipelines for automated pull request gating, SARIF code scanning uploads, and inline code annotations.

---

## 1. GitHub Actions (Official Action)

Create `.github/workflows/vigil.yml`:

```yaml
name: Vigil Security & Quality Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    name: Vigil Audit Battery
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Vigil
        uses: GuardianVigil-Lab/vigil/action.yml@main
        with:
          battery: 'review'
          github_token: ${{ secrets.GITHUB_TOKEN }}
          sarif_upload: 'true'

      - name: Archive Vigil Markdown Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vigil-report
          path: reports/vigil-review.md
```

---

## 2. GitLab CI / CD

Add to `.gitlab-ci.yml`:

```yaml
vigil-review:
  image: docker:24.0
  services:
    - docker:24.0-dind
  stage: test
  variables:
    DOCKER_HOST: tcp://docker:2375
  script:
    - docker run --rm -v "$(pwd):/workspace" ghcr.io/guardianvigil-lab/vigil:latest review
  artifacts:
    when: always
    reports:
      sast: reports/vigil.sarif
    paths:
      - reports/vigil-review.md
```

---

## 3. Git Pre-Commit Hook

Install Vigil as a fast pre-commit ratchet:

```bash
cat <<'HOOK_EOF' > .git/hooks/pre-commit
#!/usr/bin/env bash
echo "Running Vigil fast pre-commit check..."
docker run --rm -v "$(pwd):/workspace" ghcr.io/guardianvigil-lab/vigil:latest fast
HOOK_EOF
chmod +x .git/hooks/pre-commit
```
