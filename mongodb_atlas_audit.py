#!/usr/bin/env python3
"""
Script to fetch IP whitelist data from MongoDB Atlas projects.
Prints raw responses to stdout.
"""

import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB Atlas Configuration
ATLAS_BASE_URL = "https://cloud.mongodb.com"

def parse_cookies_from_string(cookie_string):
    """Parse cookies from a browser cookie string."""
    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies

def fetch_projects():
    """Fetch projects from MongoDB Atlas API and return a dictionary of project names and IDs."""
    url = f"{ATLAS_BASE_URL}/orgs/5f91aaaaf7990465218101c5/groups"
    session_cookies = parse_cookies_from_string(COOKIE_STRING)
    headers = {
        'accept': '*/*',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    }
    
    try:
        response = requests.get(url, headers=headers, cookies=session_cookies)
        response.raise_for_status()
        projects_data = response.json()
        projects = {project['name']: project['id'] for project in projects_data}
        return projects
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch projects: {e}")
        return {}

def get_ip_whitelist(project_id, project_name):
    """Get IP whitelist for a specific project and check for public IPs."""
    url = f"{ATLAS_BASE_URL}/nds/{project_id}/ipWhitelist"
    
    session_cookies = parse_cookies_from_string(COOKIE_STRING)
    
    headers = {
        'accept': '*/*',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'referer': f'https://cloud.mongodb.com/v2/{project_id}',
        'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'x-requested-with': 'XMLHttpRequest'
    }
    
    try:
        response = requests.get(url, headers=headers, cookies=session_cookies)
        
        # Check if 0.0.0.0/0 is present in the response
        if '0.0.0.0/0' in response.text or '0.0.0.0' in response.text:
            # Fetch cluster names
            clusters_url = f"{ATLAS_BASE_URL}/nds/{project_id}/users"
            clusters_response = requests.get(clusters_url, headers=headers, cookies=session_cookies)
            clusters = []
            if clusters_response.ok:
                clusters_data = clusters_response.json()
                if isinstance(clusters_data, list):
                    seen_clusters = set()
                    for user_entry in clusters_data:
                        if isinstance(user_entry, dict) and 'scopes' in user_entry:
                            for scope in user_entry['scopes']:
                                if scope.get('type') == 'CLUSTER':
                                    cluster_name = scope.get('name', 'Unknown')
                                    if cluster_name not in seen_clusters:
                                        clusters.append(cluster_name)
                                        seen_clusters.add(cluster_name)
            return "YES", clusters
        else:
            return "NO", []
        
    except requests.exceptions.RequestException as e:
        return "ERROR", []

def fetch_all_projects():
    """Fetch IP whitelist for all projects and display cluster names if public IP is found."""
    print("=" * 80)
    print("MongoDB Atlas IP Whitelist Checker - 0.0.0.0/0 Detection")
    print("=" * 80)
    print()
    
    total_projects = len(PROJECTS)
    
    for idx, (project_name, project_id) in enumerate(PROJECTS.items(), 1):
        result, clusters = get_ip_whitelist(project_id, project_name)
        
        if result == "YES":
            status = f"⚠️  YES - Clusters: {', '.join(clusters) if clusters else 'None'}"
        elif result == "NO":
            status = "✅ NO"
        else:
            status = "❌ ERROR"
        
        print(f"[{idx:2}/{total_projects}] {project_name:40} - {status}")

if __name__ == "__main__":
    COOKIE_STRING = os.getenv('ATLAS_COOKIES', '')
    if not COOKIE_STRING:
        print("ERROR: No cookies in .env file!")
        print("\nCreate a .env file with:")
        print('ATLAS_COOKIES="your_cookie_string_here"')
        exit(1)
    
    PROJECTS = fetch_projects()
    
    try:
        fetch_all_projects()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        exit(1)