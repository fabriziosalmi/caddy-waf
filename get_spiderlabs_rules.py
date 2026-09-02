import requests
import re
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_rules(rule_text):
    """
    Extracts individual ModSecurity rules from rule file content using regex.
    
    Args:
        rule_text (str): Content of ModSecurity rule file
        
    Returns:
        list: List of dictionaries containing parsed rule information
    """
    rules = []
    # Join ModSecurity line continuations first, then match `SecRule VARIABLES
    # "OPERATOR" ACTIONS`. The operator is a quoted string that may contain escaped
    # quotes, so `(?:\\.|[^"\\])*` avoids truncating it (same fix as issue #149).
    rule_text = re.sub(r"\\\s*\n\s*", " ", rule_text)
    rule_pattern = re.compile(
        r'^\s*SecRule\s+(?P<variables>\S+)\s+"(?P<expression>(?:\\.|[^"\\])*)"\s+(?P<actions>.*?)(?=^\s*SecRule|\Z)',
        re.MULTILINE | re.DOTALL,
    )

    for match in rule_pattern.finditer(rule_text):
        try:
            variables = match.group("variables")
            actions = match.group("actions")
            # Keep @rx rules (strip the operator); skip non-regex operators.
            expr = match.group("expression").strip()
            op = re.match(r'@(\w+)\s+(.*)', expr, re.DOTALL)
            if op:
                if op.group(1) != 'rx':
                    continue
                pattern = op.group(2)
            else:
                pattern = expr
            
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
                logging.warning(f"Invalid regex pattern in rule {rule_id.group(1)}: {pattern}")
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

def download_spiderlabs_rules(output_path):
    """Downloads and processes SpiderLabs ModSecurity rules."""
    repo_url = "SpiderLabs/owasp-modsecurity-crs"
    rules_dir = "rules"
    all_rules = []
    headers = {}
    
    try:
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        
        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue
            
            time.sleep(1)
            response = requests.get(file["download_url"], headers=headers)
            logging.info(f"Processing rule file: {file['name']}")
            
            rules = extract_rules(response.text)
            all_rules.extend(rules)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")
        return
        
    with open(output_path, 'w') as f:
        json.dump(all_rules, f, indent=2)
    logging.info(f"Saved {len(all_rules)} rules to {output_path}")

if __name__ == "__main__":
    output_path = "spiderlabs_rules.json"
    download_spiderlabs_rules(output_path)
