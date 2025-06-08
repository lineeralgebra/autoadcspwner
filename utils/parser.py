def parse_stdout_output(stdout_text):
    """
    Parses the certipy-ad find -text output
    and extracts templates with vulnerabilities.

    Returns a list of dicts:
    [
        {
            "ca_name": "...",
            "template_name": "...",
            "vuln": "ESC1"
        },
        ...
    ]
    """
    results = []
    lines = stdout_text.splitlines()

    current_ca = None
    current_template = None
    vuln_type = None

    for line in lines:
        line = line.strip()

        # CA name line example: "CA Name                             : sequel-DC-CA"
        if line.startswith("CA Name"):
            current_ca = line.split(":",1)[1].strip()

        # Template name line example: "Template Name                       : UserAuthentication"
        if line.startswith("Template Name"):
            current_template = line.split(":",1)[1].strip()

        # Vulnerabilities line example: "[!] Vulnerabilities"
        if "[!] Vulnerabilities" in line:
            vuln_type = None  # reset for new section

        # Example vuln line: "  ESC1                              : Enrollee supplies subject and template allows client authentication."
        if line.startswith("ESC1"):
            vuln_type = "ESC1"

        # If we collected all three, add to results
        if current_ca and current_template and vuln_type:
            results.append({
                "ca_name": current_ca,
                "template_name": current_template,
                "vuln": vuln_type
            })
            # reset vuln_type for next template
            vuln_type = None

    return results
