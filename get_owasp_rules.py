import requests  # For making HTTP requests to GitHub API and downloading files
import re        # For regular expression pattern matching
import json      # For JSON serialization
import time      # For adding delays between API requests

def download_owasp_rules(repo_url, rules_dir, output_path):
    """
    Downloads and processes OWASP ModSecurity Core Rule Set (CRS) files from GitHub.
    
    Args:
        repo_url (str): GitHub repository path (e.g., 'coreruleset/coreruleset')
        rules_dir (str): Directory containing rule files in the repository
        output_path (str): Path where processed rules will be saved as JSON
    """
    all_rules = []
    headers = {}  # Can be used to add GitHub API token if needed
    
    try:
        # Construct GitHub API URL to list contents of rules directory
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        
        # Process each .conf file in the directory
        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue
                
            # Add delay to avoid hitting GitHub API rate limits
            time.sleep(1)
            response = requests.get(file["download_url"], headers=headers)
            print(f"Processing rule file: {file['name']}")
            
            # Extract rules from file content and add to collection
            rules = extract_rules(response.text)
            all_rules.extend(rules)
            
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return
        
    # Save processed rules to JSON file
    with open(output_path, 'w') as f:
        json.dump(all_rules, f, indent=2)
    print(f"Saved {len(all_rules)} rules to {output_path}")

def extract_rules(rule_text):
    """
    Extracts individual ModSecurity rules from rule file content using regex.
    
    Args:
        rule_text (str): Content of ModSecurity rule file
        
    Returns:
        list: List of dictionaries containing parsed rule information
    """
    rules = []
    # ModSecurity wraps long rules across lines with a trailing backslash; join those
    # continuations first, otherwise a multi-line SecRule is parsed in pieces.
    rule_text = re.sub(r"\\\s*\n\s*", " ", rule_text)
    # Match `SecRule VARIABLES "OPERATOR" ACTIONS`. The operator is a quoted string that
    # may itself contain escaped quotes (e.g. @rx "...\"..."), so the old `"([^"]+)"`
    # truncated any CRS rule with a `\"` in it into an invalid pattern (issue #149).
    # `(?:\\.|[^"\\])*` consumes escaped chars correctly; rules are bounded at line-start.
    rule_pattern = re.compile(
        r'^\s*SecRule\s+(?P<variables>\S+)\s+"(?P<expression>(?:\\.|[^"\\])*)"\s+(?P<actions>.*?)(?=^\s*SecRule|\Z)',
        re.MULTILINE | re.DOTALL,
    )

    for match in rule_pattern.finditer(rule_text):
        try:
            variables = match.group("variables")
            actions = match.group("actions")
            # The quoted operator is `@<op> <argument>`. caddy-waf is a regex engine,
            # so keep @rx rules (using the argument as the pattern) and skip non-regex
            # operators (@pm, @streq, @detectSQLi, …) that cannot be expressed as a regex.
            expr = match.group("expression").strip()
            op = re.match(r'@(\w+)\s+(.*)', expr, re.DOTALL)
            if op:
                if op.group(1) != 'rx':
                    continue
                pattern = op.group(2)
            else:
                pattern = expr  # a bare pattern is an implicit @rx
            
            # Extract key rule properties using regex
            rule_id = re.search(r'id:(\d+)', actions)
            severity = re.search(r'severity:\'?([^,\'\s]+)', actions)
            action = re.search(r'action:\'?([^,\'\s]+)', actions)
            phase = re.search(r'phase:(\d+)', actions)
            description = re.search(r'msg:\'?([^\']+)\'', actions)
            
            if not rule_id:
                continue
                
            # Handle special characters in pattern
            pattern = pattern.replace('[CDATA[', '\\[CDATA\\[')
            
            # Validate regex pattern
            try:
                re.compile(pattern)
            except re.error:
                print(f"Invalid regex pattern in rule {rule_id.group(1)}: {pattern}")
                continue
                
            # Extract targeted variables from rule
            targets = []
            if variables:
                # List of possible ModSecurity variables to check for
                for target in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS", 
                             "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT", 
                             "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP"]:
                    if target in variables.upper():
                        targets.append(target)
            
            # Set default values if properties are missing
            severity_val = severity.group(1) if severity else "LOW"
            action_val = action.group(1) if action else "log"
            description_val = description.group(1) if description else "No description provided."
            
            # Calculate rule score based on severity and action
            score = 0 if action_val == "pass" else \
                    5 if action_val == "block" else \
                    4 if severity_val.upper() == "HIGH" else \
                    3 if severity_val.upper() == "MEDIUM" else 1
            
            # Create rule dictionary with extracted information
            rule = {
                "id": rule_id.group(1),
                "phase": int(phase.group(1)) if phase else 2,
                "pattern": pattern,
                "targets": targets,
                "severity": severity_val,
                "action": action_val,
                "score": score,
                "description": description_val
            }
            rules.append(rule)
            
        except (AttributeError, ValueError) as e:
            continue
            
    return rules

if __name__ == "__main__":
    # Configuration for downloading OWASP Core Rule Set
    repo_url = "coreruleset/coreruleset"
    rules_dir = "rules"
    output_path = "rules.json"
    
    download_owasp_rules(repo_url, rules_dir, output_path)
