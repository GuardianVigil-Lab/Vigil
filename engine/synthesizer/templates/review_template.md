# Vigil Security & Quality Audit Report

**Status:** {VERDICT_BADGE}  
**Date:** {GENERATED_AT}  
**Target Workspace:** `{WORKSPACE_NAME}`  
**Commit/Ref:** `{GIT_COMMIT}`  

---

## 1. Executive Summary

Vigil audited `{WORKSPACE_NAME}` across 6 engineering pillars (AST Linting, Junk Pruning, SAST/SCA Hardening, VAPT, QA Invariants, and Container Architecture).

| Severity | Count | Blockers |
| :--- | :--- | :--- |
| **P0 (Critical)** | {COUNT_P0} | {BLOCKER_P0} |
| **P1 (High)** | {COUNT_P1} | {BLOCKER_P1} |
| **P2 (Medium)** | {COUNT_P2} | Non-blocking |
| **P3 (Low / Info)** | {COUNT_P3} | Non-blocking |

---

## 2. Pillar & Scanner Matrix

| Battery / Tool | P0 | P1 | P2 | P3 | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
{SCANNER_ROWS}

---

## 3. High & Critical Findings (P0 & P1)

{CRITICAL_FINDINGS_SECTION}

---

## 4. Medium & Low Advisory Notices (P2 & P3)

{ADVISORY_FINDINGS_SECTION}

---

## 5. Audit Sign-off

- **SARIF Specification:** SARIF 2.1.0 emitted to `reports/vigil.sarif`
- **Zero-Host Dependencies:** Verified in Vigil container runtime
- **Verdict:** {VERDICT_TEXT}
