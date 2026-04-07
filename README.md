# Local Dev Sentinel

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/local-dev-sentinel.svg?style=social&label=Stars&maxAge=2592000)](https://github.com/yourusername/local-dev-sentinel/stargazers)
[![PyPI version](https://badge.fury.io/py/local-dev-sentinel.svg)](https://badge.fury.io/py/local-dev-sentinel)

**Local Dev Sentinel** is a cross-platform command-line interface (CLI) tool designed to continuously audit local development environments for security vulnerabilities, dependency conflicts, and configuration drift. Built for individual developers and small engineering teams, it ensures your local environment matches production security standards without requiring cloud dependencies or external agents.

## Features

*   **🛡️ Security Auditing:** Scans directories and environment variables to identify sensitive data exposure and configuration drift.
*   **📦 Dependency Analysis:** Analyzes package manifests (`requirements.txt`, `package.json`) against vulnerability databases to flag outdated or risky libraries.
*   **✅ Configuration Validation:** Validates local config files against security best practices and standard operational protocols.
*   **📊 Comprehensive Reporting:** Generates human-readable health reports in CLI format, as well as structured JSON or HTML for integration with dashboards.
*   **🔧 Automated Remediation:** Analyzes audit results and suggests or executes commands to remediate common security and configuration issues.
*   **📈 Trend Analysis:** Tracks audit findings over time to detect recurring patterns or regressions in the development environment.
*   **🚀 CI/CD Integration:** Pushes audit reports to CI/CD pipelines or external dashboards for centralized visibility and alerting.

## Installation

**System Requirements:**
*   Python 3.8+
*   pip

To install the latest stable release from PyPI:

```bash
pip install local-dev-sentinel
```

Alternatively, to install the latest development version directly from GitHub:

```bash
pip install git+https://github.com/yourusername/local-dev-sentinel.git
```

## Quick Start

Run a full security audit on your current working directory to get an immediate health check.

```bash
local-dev-sentinel scan
```

**Example Output:**
```text
[INFO] Initializing Local Dev Sentinel v1.0.0...
[INFO] Scanning directory: /path/to/project
[WARN] 1 Sensitive Data Leak detected: .env contains unmasked secret
[WARN] 2 Outdated Dependencies found: requests, django
[INFO] Generated Report: report.html
[SUCCESS] Audit complete. See report for details.
```

## Usage

The tool supports various subcommands and options to tailor the audit process to your needs.

### Basic Scanning
Run a standard audit including all enabled modules:
```bash
local-dev-sentinel scan --path ./src --verbose
```

### Custom Output Formats
Generate structured reports for automation pipelines:
```bash
local-dev-sentinel scan --format json --output audit-results.json
local-dev-sentinel scan --format html --output security-report.html
```

### Specific Module Execution
Target specific areas of your environment:
```bash
# Check dependencies only
local-dev-sentinel check --dependency-manager pip

# Validate configuration files only
local-dev-sentinel validate --config .env --config config.yaml

# View history of past scans
local-dev-sentinel history
```

### Exporting to CI/CD
Send reports to an external endpoint or dashboard:
```bash
local-dev-sentinel export --type jenkins --url http://ci-server/job/local-dev
```

### Fixing Issues
Attempt to automatically remediate common issues:
```bash
local-dev-sentinel fix --interactive
```

## Architecture

The tool is modular, allowing for extensibility and focused audits. The core architecture consists of the following modules:

| Module | Description |
| :--- | :--- |
| **environment_scanner** | Instruments local directories and environment variables to identify sensitive data exposure and configuration drift. |
| **dependency_checker** | Analyzes package manifests (`requirements.txt`, `package.json`) against vulnerability databases. |
| **config_validator** | Validates local config files against security best practices and standard operational protocols. |
| **report_generator** | Produces human-readable health reports in CLI and structured formats (JSON, HTML). |
| **fix_suggester** | Analyzes audit results and automatically suggests or executes commands to remediate issues. |
| **history_logger** | Tracks audit findings over time to detect recurring patterns or regressions. |
| **exporter** | Pushes audit reports to CI/CD pipelines or external dashboards for centralized visibility. |

## Contributing

We welcome contributions from the community! To contribute, please follow these steps:

1.  **Fork** the repository.
2.  Create a new branch: `git checkout -b feature/amazing-feature`.
3.  Make your changes and ensure tests pass.
4.  Commit your changes: `git commit -m 'Add some amazing feature'`.
5.  Push to the branch: `git push origin feature/amazing-feature`.
6.  Open a **Pull Request**.

Please ensure you adhere to the existing code style and add tests for new functionality.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```text
MIT License

Copyright (c) 2023 Local Dev Sentinel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```