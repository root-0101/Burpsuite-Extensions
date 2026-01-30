# Unified URL Minimizer Walkthrough

The **Unified URL Minimizer** is a Burp Suite extension designed to declutter your HTTP history by identifying and tagging duplicate requests. It helps researchers focus on unique interactions rather than sift through repetitive logs.

## Core Features

- **Native History Optimization**: Automatically tags duplicate items in the Burp Proxy history with a "duplicate" comment.
- **Custom Response-Based Tab**: A dedicated tab to view unique requests based on content length, URL, and host.
- **Background Processing**: Heavy lifting is performed in background threads to ensure Burp remains responsive.
- **Context Menu Integration**: Easily send items from any Burp tab to the Minimizer for analysis.
- **Quick Actions**: Right-click on any item to send it to Repeater, Intruder, or copy as a `curl` command.

## How to Use

### 1. Minimizing Native History
1. Navigate to the **URL Minimizer** tab.
2. Click **Minimize Native History**.
3. The extension will scan your existing proxy history and add a "duplicate" comment to redundant entries.

### 2. Manual Analysis
1. Right-click any request in Burp (Proxy, Repeater, etc.).
2. Select **Send to URL Minimizer**.
3. If the request is unique (based on URL, Host, and Response Length), it will appear in the URL Minimizer table.

## Deduplication Logic
The extension considers a request a duplicate if it matches an existing entry's:
- **Response Content-Length**
- **URL Path**
- **Host**
- **Port**
- **Protocol**
