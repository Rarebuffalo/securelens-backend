---
name: 'Feature: Automated Patches / Merge Requests'
about: Template for applying code patches and committing fixes.
title: 'Feature: Automated Patches / Merge Requests'
labels: ['help wanted', 'enhancement']
assignees: ''
---

## Description

We want to close the loop on codebase remediation by letting the CLI suggest and commit code fixes automatically.

## Goal

Implement a command (or interactive REPL slash command) that takes an AI-generated code patch, applies it to the local codebase, and creates a git branch or commit.

## Requirements

1. Retrieve the code remediation suggested by the LLM.
2. Write the patch safely to the target file.
3. Optionally run a validation check (e.g. `pytest` or compiler checks) to verify the patch doesn't break tests.
4. Automatically create a local feature branch and git commit with the fix.
