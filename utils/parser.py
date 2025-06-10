def parse_stdout_output(stdout_text):
    results = []
    lines = stdout_text.splitlines()

    current_ca = None
    current_template = None
    vuln_type = None
    is_in_ca_section = False

    for line in lines:
        line = line.strip()

        if line.startswith("CA Name"):
            current_ca = line.split(":", 1)[1].strip()
            is_in_ca_section = True
            current_template = None  # Reset template context

        if line.startswith("Template Name"):
            current_template = line.split(":", 1)[1].strip()
            is_in_ca_section = False  # Now we're in a template section

        if "[!] Vulnerabilities" in line:
            vuln_type = None  # Reset for new block

        if line.startswith("ESC1"):
            vuln_type = "ESC1"
        elif line.startswith("ESC4"):
            vuln_type = "ESC4"
        elif line.startswith("ESC7"):
            vuln_type = "ESC7"

        if vuln_type == "ESC7" and current_ca and is_in_ca_section:
            results.append({
                "ca_name": current_ca,
                "template_name": None,
                "vuln": "ESC7"
            })
            vuln_type = None

        if current_ca and current_template and vuln_type and not is_in_ca_section:
            results.append({
                "ca_name": current_ca,
                "template_name": current_template,
                "vuln": vuln_type
            })
            vuln_type = None

    return results
