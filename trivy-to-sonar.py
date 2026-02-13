import json
import sys
import os

SEVERITY_MAP = {
    "CRITICAL": "BLOCKER",
    "HIGH": "CRITICAL",
    "MEDIUM": "MAJOR",
    "LOW": "MINOR",
    "UNKNOWN": "INFO"
}

def get_target_file(result, dockerfile_path):
    origin_class = result.get('Class', 'os-pkgs')
    original_target = result.get('Target', 'unknown')
    
    if origin_class == 'os-pkgs' or 'my-app' in original_target:
        return dockerfile_path
    
    return original_target

def create_issue(engine_id, rule_id, severity, message, file_path, line):
    return {
        "engineId": engine_id,
        "ruleId": rule_id,
        "type": "VULNERABILITY",
        "severity": severity,
        "primaryLocation": {
            "message": message,
            "filePath": file_path,
            "textRange": {
                "startLine": line
            }
        }
    }

def process_vulnerabilities(result, target_file):
    issues = []
    for vuln in result.get('Vulnerabilities', []):
        severity = SEVERITY_MAP.get(vuln.get('Severity'), "INFO")
        
        pkg = vuln.get('PkgName', 'unknown')
        ver = vuln.get('InstalledVersion', '?')
        fixed = vuln.get('FixedVersion', 'none')
        title = vuln.get('Title', '')
        vuln_id = vuln.get('VulnerabilityID', 'UNKNOWN')
        
        msg = f"[{vuln.get('Severity')}] {pkg} ({ver}) - Fixed in: {fixed}. {title}"
        
        issues.append(create_issue(
            "Trivy", vuln_id, severity, msg, target_file, 1
        ))
    return issues

def process_misconfigurations(result, target_file):
    issues = []
    for misconf in result.get('Misconfigurations', []):
        severity = SEVERITY_MAP.get(misconf.get('Severity'), "MAJOR")
        line = misconf.get('IacMetadata', {}).get('StartLine', 1)
        msg = misconf.get('Message', 'Misconfiguration')
        rule_id = misconf.get('ID', 'UNKNOWN')

        issues.append(create_issue(
            "Trivy-IaC", rule_id, severity, msg, target_file, line
        ))
    return issues

def trivy_to_sonar(trivy_report_file, output_file):
    try:
        with open(trivy_report_file, 'r') as f:
            trivy_data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return

    sonar_issues = []
    dockerfile_path = "Dockerfile" if os.path.exists("Dockerfile") else "."

    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            target_file = get_target_file(result, dockerfile_path)
            
            sonar_issues.extend(process_vulnerabilities(result, target_file))
            sonar_issues.extend(process_misconfigurations(result, target_file))

    output = {"issues": sonar_issues}
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Sonar report generated with {len(sonar_issues)} issues anchored to {dockerfile_path}.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 trivy-to-sonar.py <input.json> <output.json>")
    else:
        trivy_to_sonar(sys.argv[1], sys.argv[2])