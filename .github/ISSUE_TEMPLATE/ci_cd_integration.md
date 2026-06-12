---
name: 'Feature: CI/CD Integration Packages'
about: Template for building GitHub Actions and GitLab Runner wrappers.
title: 'Feature: CI/CD Integration Packages (GitHub Actions & GitLab Runner)'
labels: ['help wanted', 'enhancement']
assignees: ''
---

## Description

We want to make it easy for developers to integrate SecureLens into their CI/CD pipelines.

## Goal

Create a reusable GitHub Action and GitLab Runner template that runs the `securelens` CLI inside workflow pipelines.

## Requirements

1. Wrap the CLI command `securelens scan` so it can run inside a container in GitHub Actions.
2. Implement configuration options to pass the `--ci` and `--fail-on` flags.
3. Ensure the action outputs logs cleanly and fails the build step with a non-zero exit code if critical or high vulnerabilities are detected.
