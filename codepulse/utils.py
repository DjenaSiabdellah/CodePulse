# Author: Djena Siabdellah
# Description: has utility functions for fetching URLs and detecting security vulnerabilities like XSS and SQL Injection in CodePulse.
# Reference 
# https://github.com/tomoyk/xss-study/blob/master/f.html 
# https://github.com/boloto1979/Code-Sentinel/blob/main/vulnerabilities/xss/xss_vulnerabilities.py
# https://github.com/boloto1979/Code-Sentinel/blob/main/vulnerabilities/injection/code_injection_vulnerabilities.py
# https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
# https://stackoverflow.com/questions/24723/best-regex-to-catch-xss-cross-site-scripting-attack-in-java 
# https://docs.python.org/3/howto/regex.html
# https://owasp.org/www-community/attacks/SQL_Injection
# https://owasp.org/www-community/attacks/xss/ 
# https://www.softwaretestinghelp.com/cross-site-scripting-xss-attack-test/
# https://www.w3schools.com/python/python_regex.asp

import requests
import logging
import re  

# This essentailly sets up logging to help me enable tracking of information and errors 
logger = logging.getLogger(__name__)

def fetch_url(url):
    try:
        # This attempts to retrieve content from the specified URL
        response = requests.get(url)
        response.raise_for_status()  # This will raise an exception
        # This returns the text content of the fetched URL, HTML or similar web content
        return response.text
    except requests.RequestException as e:
        # this Logs any errors encountered during the fetching process
        logger.error(f"Error fetching URL {url}: {e}")
        # this will return None if an error occurs to signify the fetch was unsuccessful
        return None

def detect_xss_vulnerability(html_content):
    # These are the patterns to detect common XSS vectors with severity and remediation - 
    patterns = {
        "Inline script": {
            "pattern": r"<script.*?>.*?</script>",
            "severity": "High",
            "remediation": """Event handlers and inline scripts can be blocked using Content Security Policy (CSP). -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Javascript pseudo-protocol": {
            "pattern": r"javascript:[^\s]*",
            "severity": "High",
            "remediation": """Sanitize inputs to remove or avoid 'javascript:' protocol. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Inline event handlers": {
            "pattern": r"(on\w+=['\"]?)(?!http|https)[^\s>]*",
            "severity": "Medium",
            "remediation": """Remove inline event handlers and use event transfer from JS code. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Suspicious src or href attributes": {
            "pattern": r"(src|href)=['\"]?(?!http|https|\/)[^\s>]*['\"]?",
            "severity": "Medium",
            "remediation": """Make sure that the src or href attributes can only include legitimate, sanitized URLs. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Document cookie access": {
            "pattern": r"document\.cookie",
            "severity": "Medium",
            "remediation": """Restrict and secure cookie access via HTTP headers. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Window location manipulation": {
            "pattern": r"window\.location",
            "severity": "Medium",
            "remediation": """Restrict and secure cookie access using HTTP headers.-- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Use of eval()": {
            "pattern": r"eval\s*\(",
            "severity": "High",
            "remediation": """Think about implementing safer alternatives instead of eval() rather than using it. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        }
    }
    vulnerabilities = []
    # will go over each defined pattern and check if it is present in the HTML content
    for description, info in patterns.items():
        if re.search(info["pattern"], html_content, re.IGNORECASE):
            # If a pattern matches, append the vulnerability description, severity, and remediation advice to the list
            vulnerabilities.append({
                "description": description,
                "severity": info["severity"],
                "remediation": info["remediation"]
            })
    # Return the list of detected vulnerabilities; if none are found, return a default message indicating no vulnerabilities
    return vulnerabilities if vulnerabilities else [{"description": "No XSS vulnerabilities detected.", "severity": "None", "remediation": "No action needed."}]

def detect_sql_injection(html_content):
    # define patterns for detecting SQL Injection vulnerabilities
    patterns = {
        "Tautology-based SQL Injection": {
            "pattern": r"OR 1=1",
            "severity": "High",
            "remediation": """For a solution past this issue, use prepared statements or parameterized queries. -- Please review the following guide on how to fix SQL injection vulnerabilities: 
                                         '<a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection Guide</a> '
                                         'and <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">https://owasp.org/www-community/attacks/sql-injection</a>"""
        },
        "Malicious SQL code": {
            "pattern": r"(SELECT|INSERT|DELETE|UPDATE) .*",
            "severity": "High",
            "remediation": """To prevent SQL injection, use parameterized queries and appropriate input validation. -- Please review the following guide on how to fix SQL injection vulnerabilities: 
                                         '<a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection Guide</a> '
                                         'and <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">https://owasp.org/www-community/attacks/sql-injection</a>"""
        }
    }
    vulnerabilities = []
    # Scan the HTML content for each pattern and record any matches with their details
    for description, info in patterns.items():
        # Extract the pattern from the dictionary
        pattern = info["pattern"]
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "description": description,
                "severity": info["severity"],
                "remediation": info["remediation"]
            })
    # Return detected vulnerabilities or a default message if no issues are found
    return vulnerabilities if vulnerabilities else [{"description": "No SQL Injection vulnerabilities detected.", "severity": "None", "remediation": "No action needed."}]


