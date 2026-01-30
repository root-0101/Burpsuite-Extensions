# Burp Suite Extensions Library
Welcome to my personal collection of custom Burp Suite extensions. These tools are designed to streamline bug bounty workflows and enhance security testing efficiency.

## Extension Overview

| Extension Name | Description | Documentation |
| :--- | :--- | :--- |
| **Unified URL Minimizer** | Deduplicate HTTP history and tag redundant proxy entries automatically. | [Read Walkthrough](walkthroughs/unified-url-minimizer.md) |
| **Cloud Bucket Scanner** | Scan requests and responses for leaked AWS S3, Azure Blob, and GCP buckets. | [Read Walkthrough](walkthroughs/cloud-bucket-scanner.md) |

## How to Install

1. Ensure you have **Jython** (Standalone JAR) configured in Burp Suite (**Extender > Options > Python Environment**).
2. Download the desired `.py` file from this repository.
3. In Burp Suite, go to **Extender > Extensions**.
4. Click **Add**, select **Extension Type: Python**, and choose the script file.

## Future Additions
This repository is actively maintained. New extensions targeting common bug bounty pain points will be added regularly.

---
*Created for automated security testing and efficient log analysis.*

