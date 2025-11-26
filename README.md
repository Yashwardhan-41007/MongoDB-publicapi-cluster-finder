# MongoDB Atlas Audit Tool

A Python script to audit MongoDB Atlas projects and clusters for overly permissive IP access lists. It identifies any entries with `0.0.0.0/0`, which allows access from anywhere, posing a significant security risk.

## Features

- **Cookie-Based Authentication**: Uses browser session cookies for authentication (no API keys required)
- **Comprehensive Audit**: Scans all projects and clusters within a MongoDB Atlas organization
- **Detailed Reporting**: Generates both console output and JSON reports
- **Security Focus**: Identifies dangerous `0.0.0.0/0` IP access list entries

## Prerequisites

- Python 3.6 or higher
- `requests` library
- Active MongoDB Atlas account with access to the organization

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd mongodb_atlas_audit
   ```

2. **Create a virtual environment** (recommended for Python 3.14+)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # OR on Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   # OR
   pip install requests
   ```

## Configuration

### Method 1: Using .env File (Recommended)

1. **Copy the example environment file**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` file** and add your configuration:
   ```bash
   # Your MongoDB Atlas Organization ID
   ORG_ID=your_organization_id_here
   
   # MongoDB Atlas Session Cookies
   ATLAS_COOKIES="your_cookie_string_here"
   ```

3. **Get your session cookies** (see instructions below)

### Method 2: Environment Variables

Set environment variables directly in your shell:

```bash
export ORG_ID="your_organization_id_here"
export ATLAS_COOKIES="your_cookie_string_here"
```

### Method 3: Edit Script Directly

Edit `mongodb_atlas_audit.py` and update the `ORG_ID` variable and `COOKIES` dictionary.

---

### How to Get Session Cookies

This script uses cookie-based authentication from your browser session. You have multiple options:

1. Open MongoDB Atlas in your browser and log in
2. Open Developer Tools (F12 or right-click → Inspect)
3. Go to the **Network** tab
4. Refresh the page or navigate to Projects
5. Click on any request to `cloud.mongodb.com`
6. Find the **Cookie** header in the request headers
7. Copy the ENTIRE cookie string
8. Add it to your `.env` file or export as environment variable

⚠️ **Important**: These cookies expire after a few hours and will need to be refreshed.

## Usage

Activate the virtual environment (if not already activated) and run the script:

```bash
source venv/bin/activate  # On macOS/Linux
python mongodb_atlas_audit.py
```

### Example Output

```
Starting MongoDB Atlas security audit...

Using cookie-based authentication
Organization ID: 5f91aaaaf7990465218101c5

================================================================================
MongoDB Atlas IP Access List Security Audit
================================================================================

Fetching projects for organization: 5f91aaaaf7990465218101c5
Found 3 project(s) to audit

Checking project: Production (abc123)
  ⚠️  WARNING: Found 1 open access entry/entries
  Clusters affected: prod-cluster-1, prod-cluster-2
    - 0.0.0.0/0 (Comment: Temporary access)

Checking project: Development (def456)
  ✓ No open access entries found

================================================================================
AUDIT SUMMARY
================================================================================
Total projects audited: 3
Projects with 0.0.0.0/0 access: 1

⚠️  VULNERABLE PROJECTS:

Project: Production (abc123)
  Clusters: prod-cluster-1, prod-cluster-2
  Open entries: 1

✓ Detailed report saved to: mongodb_atlas_audit_report.json
```

## Output Files

### Console Output
The script prints a detailed audit report to the console, including:
- Projects scanned
- Vulnerable entries found
- Affected clusters
- Summary statistics

### JSON Report
A detailed JSON report is saved to `mongodb_atlas_audit_report.json` containing:
```json
[
  {
    "project_id": "abc123",
    "project_name": "Production",
    "clusters": ["prod-cluster-1", "prod-cluster-2"],
    "open_entries": [
      {
        "cidrBlock": "0.0.0.0/0",
        "comment": "Temporary access"
      }
    ]
  }
]
```

## Exit Codes

- `0`: No vulnerabilities found
- `N`: Number of vulnerable projects found (1-255)
- `1`: Error occurred during execution

## Security Considerations

- **Cookie Expiration**: Browser session cookies expire after a few hours. You'll need to refresh them periodically.
- **Sensitive Data**: Never commit cookies or tokens to version control.
- **Read-Only**: This script only reads data and does not modify any configurations.
- **IP Access Lists**: The `0.0.0.0/0` entry allows access from any IP address, which is a security risk for production environments.

## Troubleshooting

### "No authentication cookies provided"
- Ensure you've set the `ATLAS_COOKIES` environment variable or updated the `COOKIES` dictionary
- Verify the cookies are not expired (refresh them from your browser)

### "Failed to fetch projects"
- Check that your Organization ID is correct
- Verify your cookies are valid and not expired
- Ensure you have appropriate permissions in MongoDB Atlas

### "ModuleNotFoundError: No module named 'requests'"
- Install the requests library: `pip install requests`

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is provided as-is for security auditing purposes. Always ensure you have proper authorization before running security audits on any system.