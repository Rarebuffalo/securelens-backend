---
name: 'Feature: Dependency Lockfile Auditor'
about: Template for scanning package files against the OSV database.
title: 'Feature: Dependency Lockfile Auditor (securelens audit)'
labels: ['help wanted', 'enhancement', 'good first issue']
assignees: ''
---

## Description

We want to expand the CLI tool's capabilities to scan project dependencies for known vulnerabilities.

## Goal

Add a new CLI command `securelens audit <path>` that scans package descriptors (such as `requirements.txt` or `package.json`) and runs checks against the Open Source Vulnerability (OSV.dev) database API.

## Requirements

1. Parse common package files to extract dependency names and versions.
2. Submit query requests to the OSV API (`https://api.osv.dev/v1/query`).
3. Format the results in a clear CLI table using `rich` showing packages, affected versions, and severity.
