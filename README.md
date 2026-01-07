# Jira User Access Auditor

A Flask-based web application that scans all Jira projects to identify users with external email domains (non-company emails).

## Features

- **Complete Project Scan**: Automatically discovers and scans all Jira projects
- **External User Detection**: Identifies users without specified company email domains
- **Detailed Reporting**: Shows which external users have access to which projects
- **Role Information**: Displays user roles within each project
- **Domain Grouping**: Groups external users by their email domains
- **CSV Export**: Export results to CSV for further analysis
- **Rate Limiting**: Built-in delays to avoid overloading Jira servers

## Quick Start

1. **Double-click `run_user_auditor.bat`**
2. **Open your browser to:** http://localhost:5200
3. **Enter your Jira details:**
   - Jira Server URL (e.g., https://your-company.atlassian.net)
   - API Token (generate from Jira profile settings)
   - Company email domains to exclude (default: mycompany.com)
4. **Click "Start User Audit"**

## Configuration

### Company Email Domains
By default, the application excludes users with `@mycompany.com` emails. You can specify multiple domains separated by commas:
```
mycompany.com, company.com, subsidiary.com
```

### API Token Setup
1. Go to your Jira profile settings
2. Navigate to "Security" → "API tokens"
3. Create a new token
4. Copy the token and use it in the application

## Output

The application provides:

### Summary Dashboard
- Total projects scanned
- Number of external users found
- Number of affected projects
- Number of unique external domains

### External Users Report
- Users grouped by email domain
- Project access for each user
- User roles within projects
- Active/inactive status

### Projects Report
- Projects with external user access
- List of external users per project
- Sorted by number of external users

### CSV Export
Downloadable CSV file containing:
- User details (name, email, domain, status)
- Project access information
- User roles

## Security Considerations

- **API Token Security**: Never share or commit API tokens
- **Rate Limiting**: Application includes built-in delays to respect Jira API limits
- **Read-Only Access**: Application only reads data, never modifies Jira
- **Local Processing**: All analysis is done locally, no data sent to external services

## Technical Details

- **Framework**: Flask (Python)
- **Port**: 5200
- **API**: Uses Jira REST API v2
- **Rate Limiting**: 0.5-1 second delays between requests
- **Timeout**: 30 seconds per API request
- **Batch Size**: 50 projects per API call

## Troubleshooting

### Connection Issues
- Verify Jira URL is correct and accessible
- Check API token is valid and has appropriate permissions
- Ensure network connectivity to Jira server

### Performance
- Large Jira instances may take 10-30 minutes to scan
- Application shows progress during scanning
- Rate limiting prevents server overload

### Permissions
- API token must have project access permissions
- Some projects may be restricted and won't appear in results

## Use Cases

- **Security Audits**: Identify external users with project access
- **Compliance**: Ensure only authorized domains have access
- **Access Reviews**: Regular audits of user permissions
- **Cleanup**: Identify accounts that may need removal
- **Reporting**: Generate reports for management or compliance teams
