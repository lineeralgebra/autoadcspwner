def parse_stdout_output(stdout_text):
    results = []
    lines = stdout_text.splitlines()

    current_ca = None
    current_template = None
    vuln_type = None
    is_in_ca_section = False
    is_in_template_section = False
    disabled_extensions = []

    for line in lines:
        line = line.strip()

        if line.startswith("CA Name"):
            current_ca = line.split(":", 1)[1].strip()
            is_in_ca_section = True
            is_in_template_section = False
            current_template = None
            disabled_extensions = []  # Reset for new CA

        elif line.startswith("Template Name"):
            current_template = line.split(":", 1)[1].strip()
            is_in_ca_section = False
            is_in_template_section = True

        elif line.startswith("Disabled Extensions"):
            disabled_extensions = line.split(":", 1)[1].strip().split()
            if "1.3.6.1.4.1.311.25.2" in disabled_extensions:
                vuln_type = "ESC16"

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
        elif line.startswith("ESC16"):
            vuln_type = "ESC16"

        # Only add CA vulnerabilities in CA section
        if current_ca and is_in_ca_section and vuln_type in ["ESC7", "ESC16"]:
            results.append({
                "ca_name": current_ca,
                "template_name": None,
                "vuln": vuln_type
            })
            vuln_type = None

        # Only add template vulnerabilities in template section
        elif current_ca and current_template and vuln_type and is_in_template_section:
            results.append({
                "ca_name": current_ca,
                "template_name": current_template,
                "vuln": vuln_type
            })
            vuln_type = None

    return results
