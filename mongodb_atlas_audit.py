#!/usr/bin/env python3
"""
Script to audit MongoDB Atlas projects and clusters for overly permissive IP access lists.
Uses cookie-based authentication from your browser session.
"""

import requests
import json
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB Atlas Configuration
ORG_ID = os.environ.get('ORG_ID', '5f91aaaaf7990465218101c5')
ATLAS_BASE_URL = "https://cloud.mongodb.com"

# Cookie authentication - get these from your browser
COOKIES = {
    '__Secure-mdb-sat': '',  # Session Access Token
    '__Secure-mdb-srt': '',  # Session Refresh Token
    'cloud-user': '1',
    'mmsa-prod': ''
}

# You can also set this as an environment variable
COOKIE_STRING = os.environ.get('ATLAS_COOKIES', '')

def parse_cookies_from_string(cookie_string):
    """Parse cookies from a browser cookie string."""
    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies

def make_request(url, method='GET'):
    """Make an authenticated request to MongoDB Atlas."""
    
    # Use cookie string if provided, otherwise use COOKIES dict
    if COOKIE_STRING:
        session_cookies = parse_cookies_from_string(COOKIE_STRING)
    else:
        session_cookies = COOKIES
    
    headers = {
        'accept': '*/*',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'content-type': 'application/json',
        'referer': 'https://cloud.mongodb.com/v2',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest'
    }
    
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            cookies=session_cookies
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        # Only print errors that are not 404 (to reduce noise)
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code != 404:
                print(f"API request failed: {e}")
                print(f"Status code: {e.response.status_code}")
                print(f"Response: {e.response.text[:500]}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None

def get_all_projects():
    """Retrieve all projects in the organization."""
    url = f"{ATLAS_BASE_URL}/orgs/{ORG_ID}/groups"
    
    result = make_request(url)
    
    if result and isinstance(result, list):
        return result
    elif result and 'results' in result:
        return result['results']
    return []

def get_project_ip_access_list(project_id):
    """Get IP access list for a specific project."""
    # Use the correct NDS endpoint for IP whitelist
    url = f"{ATLAS_BASE_URL}/nds/{project_id}/ipWhitelist"
    result = make_request(url)
    
    if result and isinstance(result, list):
        return result
    elif result and 'results' in result:
        return result['results']
    
    return []

def get_project_clusters(project_id):
    """Get all clusters in a project."""
    # Use the correct NDS endpoint for clusters
    url = f"{ATLAS_BASE_URL}/nds/{project_id}/clusters"
    result = make_request(url)
    
    if result and isinstance(result, list):
        return result
    elif result and 'results' in result:
        return result['results']
    
    return []

def has_open_access(ip_entry):
    """Check if an IP access list entry allows access from anywhere."""
    cidr = ip_entry.get('cidrBlock', '')
    ip_addr = ip_entry.get('ipAddress', '')
    
    # Check for 0.0.0.0/0 or just 0.0.0.0
    return cidr == '0.0.0.0/0' or ip_addr == '0.0.0.0'

def audit_mongodb_atlas():
    """Main function to audit all projects and clusters."""
    print("=" * 80)
    print("MongoDB Atlas IP Access List Security Audit")
    print("=" * 80)
    print()
    
    vulnerable_projects = []
    
    # Get all projects
    print(f"Fetching projects for organization: {ORG_ID}")
    projects = get_all_projects()
    
    if not projects:
        print("❌ Failed to fetch projects. Please check your authentication.")
        return []
    
    print(f"Found {len(projects)} project(s) to audit\n")
    
    for project in projects:
        project_id = project.get('id') or project.get('groupId')
        project_name = project.get('name')
        
        if not project_id:
            print(f"⚠️  Skipping project with no ID: {project_name}")
            continue
        
        print(f"Checking project: {project_name} ({project_id})")
        
        # Get IP access list for the project
        access_list = get_project_ip_access_list(project_id)
        
        if not access_list:
            print(f"  ℹ️  No IP access list entries found")
            continue
        
        # Check for 0.0.0.0/0 entries
        open_entries = [entry for entry in access_list if has_open_access(entry)]
        
        if open_entries:
            # Get clusters in this project
            clusters = get_project_clusters(project_id)
            cluster_names = [cluster.get('name', 'Unknown') for cluster in clusters]
            
            vulnerable_projects.append({
                'project_id': project_id,
                'project_name': project_name,
                'clusters': cluster_names,
                'open_entries': open_entries
            })
            
            print(f"  ⚠️  WARNING: Found {len(open_entries)} open access entry/entries")
            print(f"  Clusters affected: {', '.join(cluster_names) if cluster_names else 'None'}")
            for entry in open_entries:
                comment = entry.get('comment', 'No comment')
                cidr = entry.get('cidrBlock', entry.get('ipAddress', 'Unknown'))
                print(f"    - {cidr} (Comment: {comment})")
        else:
            print(f"  ✓ No open access entries found")
        
        print()
    
    # Summary
    print("=" * 80)
    print("AUDIT SUMMARY")
    print("=" * 80)
    print(f"Total projects audited: {len(projects)}")
    print(f"Projects with 0.0.0.0/0 access: {len(vulnerable_projects)}")
    print()
    
    if vulnerable_projects:
        print("⚠️  VULNERABLE PROJECTS:")
        for vp in vulnerable_projects:
            print(f"\nProject: {vp['project_name']} ({vp['project_id']})")
            print(f"  Clusters: {', '.join(vp['clusters']) if vp['clusters'] else 'None'}")
            print(f"  Open entries: {len(vp['open_entries'])}")
        
        # Export to JSON
        with open('mongodb_atlas_audit_report.json', 'w') as f:
            json.dump(vulnerable_projects, f, indent=2)
        print("\n✓ Detailed report saved to: mongodb_atlas_audit_report.json")
    else:
        print("✓ No projects with open access found!")
    
    return vulnerable_projects

if __name__ == "__main__":
    print("Starting MongoDB Atlas security audit...\n")
    
    # Check for authentication
    has_cookies = bool(COOKIE_STRING) or any(COOKIES.values())
    
    if not has_cookies:
        print("ERROR: No authentication cookies provided!")
        print("\n" + "="*80)
        print("How to get your MongoDB Atlas session cookies:")
        print("="*80)
        print("\n1. Open MongoDB Atlas in your browser and log in")
        print("2. Open Developer Tools (F12 or right-click → Inspect)")
        print("3. Go to the 'Network' tab")
        print("4. Refresh the page or navigate to Projects")
        print("5. Click on any request to 'cloud.mongodb.com'")
        print("6. Find the 'Cookie' header in the request headers")
        print("7. Copy the ENTIRE cookie string")
        print("\nThen run the script with:")
        print('  export ATLAS_COOKIES="your_cookie_string_here"')
        print("  python mongodb_audit.py")
        print("\nOR edit the COOKIES dictionary in the script with:")
        print("  __Secure-mdb-sat: (the session access token)")
        print("  __Secure-mdb-srt: (the session refresh token)")
        print("\n⚠️  Note: These cookies expire after a few hours!")
        sys.exit(1)
    
    print(f"Using cookie-based authentication")
    print(f"Organization ID: {ORG_ID}\n")
    
    try:
        vulnerable_projects = audit_mongodb_atlas()
        
        # Exit with error code if vulnerabilities found
        sys.exit(len(vulnerable_projects))
    except Exception as e:
        print(f"Error during audit: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)