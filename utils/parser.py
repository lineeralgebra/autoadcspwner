def parse_stdout_output(stdout_text):
    results = []
    lines = stdout_text.splitlines()

    current_ca = None
    current_template = None
    vuln_type = None
    is_in_ca_section = False
    is_in_template_section = False

    for line in lines:
        line = line.strip()

        if line.startswith("CA Name"):
            current_ca = line.split(":", 1)[1].strip()
            is_in_ca_section = True
            is_in_template_section = False
            current_template = None

        elif line.startswith("Template Name"):
            current_template = line.split(":", 1)[1].strip()
            is_in_ca_section = False
            is_in_template_section = True

        elif "[!] Vulnerabilities" in line:
            vuln_type = None

        elif line.startswith("ESC1"):
            vuln_type = "ESC1"
        elif line.startswith("ESC4"):
            vuln_type = "ESC4"
        elif line.startswith("ESC7"):
            vuln_type = "ESC7"
        elif line.startswith("ESC9"):
            vuln_type = "ESC9"

        # Only add ESC7 if we're in CA section and it's actually ESC7
        if vuln_type == "ESC7" and current_ca and is_in_ca_section:
            results.append({
                "ca_name": current_ca,
                "template_name": None,
                "vuln": "ESC7"
            })
            vuln_type = None

        # Only add template vulnerabilities if we're in template section
        elif current_ca and current_template and vuln_type and is_in_template_section:
            results.append({
                "ca_name": current_ca,
                "template_name": current_template,
                "vuln": vuln_type
            })
            vuln_type = None

    return results
