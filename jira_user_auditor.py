"""
Jira User Access Auditor - Fixed Version
Scans all Jira projects to identify users without company email domains.
"""

from flask import Flask, render_template, request, jsonify, send_file
import requests
import logging
import time
from typing import List, Dict, Set
import json
import tempfile
import csv
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('JiraUserAuditor')

# Set requests logging to DEBUG to see all HTTP calls
logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'jira-user-auditor-key'

class JiraUserAuditor:
    """Audits Jira projects for users with non-company email domains."""
    
    def __init__(self, jira_url: str, access_token: str):
        self.jira_url = jira_url.rstrip('/')
        self.access_token = access_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def test_connection(self) -> bool:
        """Test connection to Jira."""
        try:
            response = self.session.get(f'{self.jira_url}/rest/api/2/myself', timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            return False
    
    def get_user_details(self, user_key: str) -> Dict:
        """Get detailed user information including email."""
        try:
            url = f'{self.jira_url}/rest/api/2/user'
            params = {'username': user_key}
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            
            # Try with key parameter if username fails
            params = {'key': user_key}
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            
            return {}
        except Exception as e:
            return {}
    
    def get_project_users(self, project_key: str, excluded_domains: List[str] = None) -> List[Dict]:
        """Get all users with access to a specific project."""
        try:
            users = []
            logger.info(f"🔍 Scanning project: {project_key}")
            
            # Get project roles
            roles_url = f'{self.jira_url}/rest/api/2/project/{project_key}/role'
            response = self.session.get(roles_url, timeout=30)
            
            if response.status_code != 200:
                logger.warning(f"⚠️ Failed to get roles for project {project_key}: HTTP {response.status_code}")
                return []
            
            roles = response.json()
            
            for role_name, role_url in roles.items():
                try:
                    role_response = self.session.get(role_url, timeout=30)
                    
                    if role_response.status_code == 200:
                        role_data = role_response.json()
                        
                        if 'actors' in role_data:
                            for actor in role_data['actors']:
                                actor_type = actor.get('type', '')
                                
                                # Handle different actor types
                                user_info = None
                                if actor_type == 'atlassian-user-role-actor':
                                    if actor.get('name') or actor.get('displayName'):
                                        user_info = actor
                                    else:
                                        user_info = actor.get('actorUser', {})
                                elif actor_type == 'user':
                                    user_info = actor
                                elif 'user' in actor:
                                    user_info = actor['user']
                                elif 'actorUser' in actor:
                                    user_info = actor['actorUser']
                                
                                if user_info and (user_info.get('key') or user_info.get('name')):
                                    user_key = user_info.get('key', user_info.get('name', ''))
                                    
                                    # Get detailed user info including email
                                    user_details = self.get_user_details(user_key)
                                    
                                    users.append({
                                        'key': user_key,
                                        'name': user_info.get('name', ''),
                                        'displayName': user_info.get('displayName', user_info.get('diisplayName', '')),
                                        'emailAddress': user_details.get('emailAddress', ''),
                                        'active': user_info.get('active', True),
                                        'role': role_data.get('name', 'Unknown')
                                    })
                    
                    time.sleep(0.2)  # Rate limiting
                    
                except Exception as e:
                    logger.warning(f"⚠️ Error processing role {role_name} for {project_key}: {str(e)}")
                    continue
            
            # Remove duplicates based on user key
            unique_users = {user['key']: user for user in users if user['key']}.values()
            unique_users_list = list(unique_users)
            
            logger.info(f"📋 DEDUPLICATION: {len(users)} total user entries -> {len(unique_users_list)} unique users")
            
            # Count external vs company users for summary
            if excluded_domains is None:
                excluded_domains = ['mycompany.com']
            
            external_count = sum(1 for user in unique_users_list 
                               if user.get('emailAddress', '').lower() and 
                               not any(user.get('emailAddress', '').lower().endswith(f'@{domain}') 
                                      for domain in excluded_domains))
            company_count = len(unique_users_list) - external_count
            
            logger.info(f"✅ PROJECT SUMMARY {project_key}: {len(unique_users_list)} unique users ({company_count} company, {external_count} external)")
            logger.info(f"📋 Excluded domains: {excluded_domains}")
            return unique_users_list
            
        except Exception as e:
            logger.error(f"🚩 Error fetching users for project {project_key}: {str(e)}")
            return []

    def audit_single_project(self, project_key: str, excluded_domains: List[str]) -> Dict:
        """Audit a single project for external users."""
        logger.info(f"🔍 Starting single project audit for: {project_key}")
        
        users = self.get_project_users(project_key, excluded_domains)
        if not users:
            return {'error': f'No users found for project {project_key} or project does not exist'}
        
        results = {
            'project_key': project_key,
            'total_users': len(users),
            'external_users': {},
            'company_users': {},
            'excluded_domains': excluded_domains,
            'scan_timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"📋 Analyzing {len(users)} users in project {project_key}")
        
        for user in users:
            email = user.get('emailAddress', '').lower()
            user_key = user['key']
            
            user_data = {
                'key': user_key,
                'name': user.get('name', ''),
                'displayName': user.get('displayName', ''),
                'emailAddress': email,
                'active': user.get('active', True),
                'role': user.get('role', 'Unknown'),
                'domain': email.split('@')[-1] if '@' in email else 'unknown'
            }
            
            if email and not any(email.endswith(f'@{domain}') for domain in excluded_domains):
                results['external_users'][user_key] = user_data
                logger.info(f"🚨 External user found: {user_data['displayName']} ({email}) - Role: {user_data['role']}")
            else:
                results['company_users'][user_key] = user_data
                logger.info(f"✅ Company user: {user_data['displayName']} ({email}) - Role: {user_data['role']}")
        
        logger.info(f"✅ Single project audit complete:")
        logger.info(f"   👥 Total users: {results['total_users']}")
        logger.info(f"   🚨 External users: {len(results['external_users'])}")
        logger.info(f"   ✅ Company users: {len(results['company_users'])}")
        
        return results

@app.route('/')
def index():
    """Main page for Jira User Auditor."""
    return render_template('user_auditor.html')

@app.route('/audit_single', methods=['POST'])
def audit_single_project():
    """Audit a single project."""
    try:
        jira_url = request.form.get('jira_url')
        access_token = request.form.get('access_token')
        project_key = request.form.get('project_key', '').strip().upper()
        excluded_domains = request.form.get('excluded_domains', 'mycompany.com').split(',')
        excluded_domains = [domain.strip() for domain in excluded_domains if domain.strip()]
        
        if not all([jira_url, access_token, project_key]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        logger.info(f"🔍 Starting single project audit for: {project_key}")
        logger.info(f"📋 Excluded domains: {excluded_domains}")
        
        auditor = JiraUserAuditor(jira_url, access_token)
        
        # Test connection
        if not auditor.test_connection():
            return jsonify({'error': 'Failed to connect to Jira. Check URL and token.'}), 401
        
        # Perform single project audit
        results = auditor.audit_single_project(project_key, excluded_domains)
        
        if 'error' in results:
            return jsonify({'error': results['error']}), 404
        
        return jsonify({
            'success': True,
            'results': results,
            'audit_type': 'single_project'
        })
        
    except Exception as e:
        logger.error(f"🚩 Single project audit error: {str(e)}")
        return jsonify({'error': f'Single project audit failed: {str(e)}'}), 500

@app.route('/export_csv', methods=['POST'])
def export_csv():
    """Export audit results to CSV."""
    try:
        data = request.get_json()
        logger.debug(f"📋 CSV Export - Raw request data: {data}")
        
        results = data.get('results', {})
        logger.debug(f"📋 CSV Export - Results keys: {list(results.keys())}")
        logger.debug(f"📋 CSV Export - External users: {results.get('external_users', {})}")
        
        external_users = results.get('external_users', {})
        logger.info(f"📋 CSV Export requested for {len(external_users)} external users")
        
        if not external_users:
            logger.warning("⚠️ No external users found for CSV export")
            return jsonify({'error': 'No external users to export'}), 400
        
        # Create temporary CSV file
        tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')
        try:
            writer = csv.writer(tmp_file)
            
            # Write header
            writer.writerow(['User Key', 'Display Name', 'Email', 'Domain', 'Active', 'Role'])
            
            # Write data for single project audit
            for user_key, user_info in external_users.items():
                logger.debug(f"📋 Writing user to CSV: {user_key} - {user_info}")
                writer.writerow([
                    user_info.get('key', ''),
                    user_info.get('displayName', ''),
                    user_info.get('emailAddress', ''),
                    user_info.get('domain', ''),
                    user_info.get('active', ''),
                    user_info.get('role', '')
                ])
            
            tmp_file.flush()  # Ensure data is written
            tmp_file.close()  # Close the file
            
            logger.info(f"✅ CSV file created: {tmp_file.name}")
            
            return send_file(
                tmp_file.name,
                as_attachment=True,
                download_name=f'jira_external_users_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                mimetype='text/csv'
            )
        except Exception as e:
            tmp_file.close()
            raise
            
    except Exception as e:
        logger.error(f"🚩 CSV export error: {str(e)}")
        import traceback
        logger.error(f"🚩 Full traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5201)