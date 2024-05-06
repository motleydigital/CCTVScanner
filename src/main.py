import argparse
import nmap
import sys

def parse_arguments():
    """ Parse CLI arguments. """
    parser = argparse.ArgumentParser(description="CCTV Vulnerability Scanner")
    parser.add_argument('--ip', required=True, help='IP address of the CCTV system')
    args = parser.parse_args()
    return args.ip

def run_nmap_scan(ip):
    """ Perform an Nmap scan to discover open ports and services. """
    scanner = nmap.PortScanner()
    try:
        # Basic service discovery
        scanner.scan(ip, arguments='-sV')
        return scanner[ip]
    except nmap.PortScannerError:
        print("Nmap not found", file=sys.stderr)
        sys.exit(1)
    except KeyError:
        print("Host seems to be down", file=sys.stderr)
        sys.exit(1)

def detect_cctv_model(scan_results):
    """ Extract make, model, and firmware from Nmap scan results. """
    # This is a placeholder for the logic to parse nmap results and extract details.
    for proto in scan_results.all_protocols():
        lport = scan_results[proto].keys()
        for port in lport:
            service = scan_results[proto][port]['product']
            version = scan_results[proto][port]['version']
            if service:
                return service, version
    return None, None  # Default if nothing specific is found

def load_modules():
    """ Dynamically load CVE modules based on configuration or detection. """
    # Placeholder for module loading logic
    modules = {}
    modules['CVE-2021-36260'] = __import__('cve_2021_36260')
    return modules

def run_scanner(ip, modules, make, model):
    """ Run vulnerability modules against the specified IP. """
    for cve, module in modules.items():
        if module.is_applicable(make, model):
            if module.run(ip):
                print(f"{ip} is vulnerable to {cve}! Please check the report for more details.")
            else:
                print(f"{ip} is not vulnerable to {cve}.")
        else:
            print(f"{cve} is not applicable to the detected CCTV model.")

def generate_report(ip, make, model, vulnerabilities):
    """ Generate a report based on the scan results. """
    report_path = f"./reports/{ip}_report.txt"
    with open(report_path, 'w') as report:
        report.write(f"CCTV IP: {ip}\nMake: {make}\nModel: {model}\n\n")
        for cve, status in vulnerabilities.items():
            report.write(f"{cve}: {'Vulnerable' if status else 'Not Vulnerable'}\n")
        print(f"Report generated at {report_path}")

if __name__ == "__main__":
    ip = parse_arguments()
    scan_results = run_nmap_scan(ip)
    make, model = detect_cctv_model(scan_results)
    if make and model:
        print(f"Detected CCTV Model: {make}, Firmware: {model}")
        modules = load_modules()
        run_scanner(ip, modules, make, model)
    else:
        # Optionally ask the user for make/model if not detectable
        make = input("Enter the make of the CCTV: ")
        model = input("Enter the model of the CCTV: ")
        modules = load_modules()
        run_scanner(ip, modules, make, model)
