# IPExtractorPro
![image](https://github.com/JafarAli-SHO/IpExtractorPro/assets/106411544/21cf65ec-6cb9-48e2-a0cf-ffeff8a42d09)

IPExtractorPro is a Python script designed to extract IP addresses from a given domain by fetching subdomains from VirusTotal and SecurityTrails APIs and performing DNS queries on the subdomains. 

## Features

- Fetch subdomains from VirusTotal API
- Fetch subdomains from SecurityTrails API
- Perform DNS queries to extract IP addresses of the subdomains
- Display results in a user-friendly format

## Requirements

- Python 3.x
- `requests` library
- `pyfiglet` library
- `termcolor` library
- `subprocess` module (comes with Python standard library)
- `dig` command (available in `dnsutils` package for Linux
- ## Installation
- **Clone the repository:**
- **Install the required Python packages:**
    sudo apt-get install dnsutils
    pip install requests pyfiglet termcolor
  ## Usage

1. **Run the script:**
   python IPExtractorPro.py

   the script will first prompt for virustotal and security trails api key after setting it the script will save a file config.txt and store the 
   api key in that file to current working directory
   
   ![image](https://github.com/JafarAli-SHO/IpExtractorPro/assets/106411544/9804738f-57a3-45fd-a02b-9c129dc98f1a)

 2.after setting the api key the script will prompt for entering the target website url
   ![image](https://github.com/JafarAli-SHO/IpExtractorPro/assets/106411544/8d15f104-550b-4a93-9637-d3999de22eaf)
