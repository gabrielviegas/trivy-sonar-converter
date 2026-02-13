# Trivy to SonarQube Converter (Docker & OS Vulnerabilities Fix)

A lightweight Python script that converts **Trivy** JSON reports into **SonarQube Generic Issue Import** format. 

**Key Feature:** It solves the "missing vulnerabilities" problem by anchoring Container OS vulnerabilities (e.g., Debian/Alpine packages) to your `Dockerfile`, ensuring they appear in the SonarQube dashboard.

## 🛑 The Problem

When scanning Docker images, Trivy finds vulnerabilities in system files (e.g., `/usr/lib/libc.so`, `/bin/bash`). 
However, when you import this report into SonarQube, **these vulnerabilities are ignored** because:
1. SonarQube only reports issues on files that exist in your Git repository.
2. System files inside the container do not exist in your source code.

This results in a clean SonarQube dashboard even when your Docker image has Critical vulnerabilities.

## ✅ The Solution

This script processes the Trivy report and applies the following logic:
1. **Anchoring:** If a vulnerability belongs to an OS Package (Class: `os-pkgs`) or the application binary, it rewrites the `filePath` to `Dockerfile` (Line 1).
2. **Severity Mapping:** Maps Trivy severities to SonarQube's strict levels (e.g., `CRITICAL` -> `BLOCKER`).
3. **Type Enforcement:** Forces the issue type to `VULNERABILITY` so it appears in the Security tab (not as a Code Smell).

## 🚀 Usage

### Prerequisites
- Python 3.x (Standard library only, no pip install needed)
- Trivy
- SonarScanner

### 1. The Script
Copy `trivy-to-sonar.py` to your project root.

### 2. Running Locally
```bash
# 1. Generate Trivy JSON
trivy image --format json --output trivy.json my-image:latest

# 2. Convert to Sonar Format
python3 trivy-to-sonar.py trivy.json sonar-report.json