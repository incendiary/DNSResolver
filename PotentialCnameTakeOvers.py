import re
from datetime import datetime

# Function to detect potential cloud service takeovers
def detect_potential_takeovers(dangling_cname_file, output_file):
    # Define patterns for known cloud services
    patterns = {
        'aws': re.compile(r'\.compute\.amazonaws\.com\.'),
        'azure': re.compile(r'\.cloudapp\.azure\.com\.'),
        'gcp': re.compile(r'\.cloud\.google\.com\.')
    }

    with open(dangling_cname_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            domain = line.strip()
            for cloud_provider, pattern in patterns.items():
                if pattern.search(domain):
                    outfile.write(f"Potential {cloud_provider.upper()} takeover candidate: {domain}\n")
                    print(f"Potential {cloud_provider.upper()} takeover candidate: {domain}")

# Get the current timestamp and format it
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
dangling_cname_file = f"dangling_cnames_{timestamp}.txt"
output_file = f"potential_takeovers_{timestamp}.txt"

# Detect potential takeovers
detect_potential_takeovers(dangling_cname_file, output_file)

print(f"Potential takeovers logged to {output_file}")
