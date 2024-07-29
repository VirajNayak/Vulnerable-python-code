import requests
from bs4 import BeautifulSoup

# Replace with your GitHub personal access token
GITHUB_TOKEN = 'your_github_token'
OWNER = 'your_repo_owner'
REPO = 'your_repo_name'

# GitHub API endpoint to fetch code scanning alerts
GITHUB_API_URL = f'https://api.github.com/repos/{OWNER}/{REPO}/code-scanning/alerts'

# Headers for GitHub API request
headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# Fetch code scanning alerts
def fetch_code_scanning_alerts():
    response = requests.get(GITHUB_API_URL, headers=headers)
    response.raise_for_status()
    return response.json()

# Fetch CWE details from CWE website
def fetch_cwe_details(cwe_id):
    cwe_url = f'https://cwe.mitre.org/data/definitions/{cwe_id}.html'
    response = requests.get(cwe_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    likelihood_tag = soup.find(string='Likelihood of Exploit')
    if likelihood_tag:
        return likelihood_tag.find_next('td').text.strip()
    return 'Unknown'

# Filter and print relevant vulnerabilities
def print_relevant_vulnerabilities(alerts):
    for alert in alerts:
        severity = alert['rule']['severity']
        if severity in ['high', 'critical']:
            cwe_id = alert['rule']['id'].split('-')[1]
            likelihood = fetch_cwe_details(cwe_id)
            if likelihood == 'High':
                print(f"Vulnerability: {alert['rule']['description']}")
                print(f"Severity: {severity.capitalize()}")
                print(f"CWE ID: {cwe_id}")
                print(f"Likelihood of Exploitability: {likelihood}")
                print('-' * 50)

if __name__ == '__main__':
    alerts = fetch_code_scanning_alerts()
    print_relevant_vulnerabilities(alerts)
