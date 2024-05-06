# CCTV Vulnerability Scanner

## Project Overview

The CCTV Vulnerability Scanner is a tool designed to assess vulnerabilities in CCTV systems. It uses Python to dynamically load modules that scan for known vulnerabilities based on the CCTV's make, model, and firmware. The tool integrates with Nmap for enhanced network scanning capabilities.

## Features

- **Host Discovery**: Identifies active devices within a specified network range.
- **Service Identification**: Determines running services to deduce device information like make, model, and firmware.
- **Modular Vulnerability Testing**: Dynamically loads testing modules specific to detected CCTV models.
- **Reporting**: Generates detailed reports outlining identified vulnerabilities and recommendations.

## Installation

### Prerequisites

- Python 3.8 or higher
- Nmap
- Git (for version control)

### Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourorg/cctv-vulnerability-scanner.git
   cd cctv-vulnerability-scanner
   ```
2. **Set Up a Virtual Environment (Recommended)**:

### Create the Virtual Environment:

- **Windows**:

  ```bash
  `python -m venv venv

  ```

- **Linux or macOS**:
  ```bash
  `python3 -m venv venv
  ```

### Activate the Virtual Environment:

- **Windows**:

  ```bash
  `.\venv\Scripts\activate

  ```

- **Linux or macOS**:
  ```bash
  `source venv/bin/activate
  ```

### Deactivate the Virtual Environment:

- **Windows, Linux or macOS**:
  ```bash
  `deactivate
  ```

### Install Dependencies:

- **Windows, Linux or macOS**:
  `pip install -r requirements.txt

## Usage

To run the CCTV Vulnerability Scanner, activate the virtual environment and execute the main script:

- **Windows, Linux or macOS**:
  ```bash
  `python src/main.py --ip <target-ip-address>
  ```

Replace <target-ip-address> with the actual IP address of the CCTV you want to scan.

## Contributing

### How to Contribute

Contributions are welcome and greatly appreciated. Every little help counts, from bug fixes to improving documentation.

### Pull Requests

- Please ensure to update tests as appropriate.
- Update the `README.md` with details of changes.
- Submit a pull request through GitHub.

### Guidelines

- Code contributions should follow the [PEP8 style guide](https://www.python.org/dev/peps/pep-0008/) for Python.
- Use clear and meaningful commit messages.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

## Support

For support, email [support@yourorg.com](mailto:support@yourorg.com) or join our Slack channel.

## Authors and Acknowledgment

- **John Doe** - Initial work - [JohnDoe](https://github.com/JohnDoe)

A full list of contributors can be found on the [contributors](https://github.com/yourorg/cctv-vulnerability-scanner/contributors) page.
