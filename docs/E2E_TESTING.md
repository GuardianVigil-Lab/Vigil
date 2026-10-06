# Vigil Containerized Playwright E2E User Persona Guide

Vigil bundles pre-installed headless Chromium and a comprehensive suite of user persona journeys inside the container, eliminating local browser installation headaches.

---

## 1. Container Hardening & Anti-Crash Flags

Running headless browsers inside Docker containers often fails due to shared memory exhaustion (`/dev/shm`) and missing sandboxing privileges. Vigil configures:

- Host argument: `--shm-size=2gb`
- Chromium flags:
  - `--no-sandbox`
  - `--disable-setuid-sandbox`
  - `--disable-dev-shm-usage`
  - `--disable-gpu`
  - `--single-process`
- Pre-installed browser path: `ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`

---

## 2. Generic Core User Journeys (`engine/e2e/core_journeys/`)

When no project-specific Playwright test suite is provided, Vigil executes 4 generic user journeys against `TARGET_URL`:

1. **Journey 1 (`01_auth_session_lifecycle.spec.ts`)**:
   - Asserts invalid login credentials yield clear error banners without server 500 crashes.
   - Verifies session cookies have `HttpOnly` and appropriate `SameSite` flags.
   - Verifies logging out invalidates session and redirects protected routes.
2. **Journey 2 (`02_dom_console_error_sweep.spec.ts`)**:
   - Crawls all standard application routes (`/`, `/dashboard`, `/settings`, etc.).
   - Catches `page.on('console')` and `page.on('pageerror')`.
   - **Any unhandled JavaScript exception or CSP violation raises a P1 Quality Failure**.
3. **Journey 3 (`03_form_boundary_fuzzing.spec.ts`)**:
   - Detects `<form>` inputs across pages.
   - Injects boundary payloads (SQL injection metacharacters, XSS snippets, oversized 5000+ character buffers).
   - Verifies graceful form validation without unhandled promise rejections or 500 crashes.
4. **Journey 4 (`04_rbac_multi_tenant_probes.spec.ts`)**:
   - Asserts unauthenticated users cannot access administrative paths (`/admin`, `/settings/billing`).
   - Asserts redirect to login or HTTP 401/403 refusal.

---

## 3. Project-Specific Test Discovery

If your workspace contains `playwright.config.ts` or an `e2e/` folder, Vigil automatically discovers and executes your project's custom test suite using the containerized Chromium runtime.
