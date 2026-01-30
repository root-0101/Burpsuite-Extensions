# Cloud Bucket & Leak Scanner Walkthrough

The **Cloud Bucket & Leak Scanner** is a powerful Burp Suite extension that passively and actively scans for leaked cloud storage assets (buckets) across AWS, Azure, and GCP.

## Core Features

- **Multi-Cloud Support**:
    - **AWS**: Detects S3 buckets (virtual-host and path-style) and S3 website endpoints.
    - **Azure**: Detects Blob, File, Table, Queue, and Data Lake storage.
    - **GCP**: Detects Google Cloud Storage buckets.
- **Passive Scanning**: Automatically extracts bucket names from all traffic passing through Burp.
- **Search & Filter**: Real-time filtering of discovered assets to quickly find relevant targets.
- **Export Capabilities**: Export discovered assets to a CSV file for reporting or further automation.
- **Bulk Processing**: Select multiple messages in Burp and send them for aggregate scanning.

## How to Use

### 1. Passive Scanning
Simply browse the target application with Burp running. The extension will automatically populate the **Cloud Scanner** tab with any discovered bucket names.

### 2. Manual/Bulk Scanning
1. Select one or more requests in the Proxy History or Logger.
2. Right-click and choose **Send to Cloud Scanner**.
3. The extension will scan the selected requests/responses for any cloud asset keywords.

### 3. Data Management
- Use the **Filter** box to narrow down results by provider or asset name.
- Click **Export CSV** to save your findings.
- **Clear All** safely wipes the current session data.

## Discovery Regex
The extension uses highly optimized regular expressions to identify assets stored in:
- HTTP URLs
- JavaScript files
- API responses
- Request bodies
