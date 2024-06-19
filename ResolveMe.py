import dns.resolver
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import argparse

# Function to resolve a domain and get all its records with retries and timeout handling
def resolve_domain(domain, custom_nameservers):
    records = {}
    retries = 3
    timeout = 10  # Timeout in seconds

    print(f"Resolving domain: {domain}")

    while retries > 0:
        try:
            this_resolver = dns.resolver.Resolver()
            this_resolver.nameservers = custom_nameservers
            this_resolver.timeout = timeout
            this_resolver.lifetime = timeout

            for qtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
                answers = this_resolver.resolve(domain, qtype, raise_on_no_answer=False)
                records[qtype] = [str(rdata) for rdata in answers]

            return records  # Return records if resolved successfully

        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            records['NXDOMAIN'] = True
            return records
        except dns.exception.Timeout:
            retries -= 1
            if retries > 0:
                print(f"Timeout occurred - {domain}. Retrying... Attempts left: {retries}")
                time.sleep(1)  # Wait for a moment before retrying
            else:
                print(f"Maximum retries exceeded for {domain}. Returning timeout message.")
                records['TIMEOUT'] = True
                return records
        except Exception as e:
            print(f"An error occurred: {e}")
            return records  # Return empty records on any other error

    return records  # Fallback in case retries are exhausted without successful resolution


# Function to resolve CNAME records recursively with retries and timeout handling
def resolve_cname_recursively(domain, custom_nameservers, dangling_cnames_log):
    resolved_records = {}
    to_resolve = [domain]

    while to_resolve:
        current_domain = to_resolve.pop(0)
        print(f"Resolving CNAME chain for: {current_domain}")
        records = resolve_domain(current_domain, custom_nameservers)
        resolved_records[current_domain] = records

        if 'CNAME' in records:
            # Add the CNAME target to the list for further resolution
            print(f"Found CNAME record, resolving next in chain: {records['CNAME']}")
            to_resolve.extend(records['CNAME'])
        elif 'A' not in records and 'AAAA' not in records:
            # Resolve the final domain for A and AAAA records if it was not a CNAME
            print(f"Final CNAME resolved. Resolving A/AAAA for: {current_domain}")
            final_records = resolve_domain(current_domain, custom_nameservers)
            resolved_records[current_domain].update(final_records)

            # Check if the final CNAME target resolves to A/AAAA records
            if 'A' not in final_records and 'AAAA' not in final_records:
                print(f"Dangling CNAME candidate: {current_domain}")
                with open(dangling_cnames_log, 'a') as dangling_log_file:
                    dangling_log_file.write(f"{current_domain}\n")

    return resolved_records


# Function to process entries
def process_line(line, custom_nameservers, dangling_cnames_log, output_results):
    parts = line.strip().split()
    if len(parts) != 1:
        return None
    domain = parts[0]
    print(domain)

    resolved_domains = {}


    if record_type == 'CNAME':
        resolved_records = resolve_cname_recursively(value, custom_nameservers, dangling_cnames_log)
        resolved_domains[domain] = resolved_records
    else:
        if domain not in resolved_domains:
            resolved_domains[domain] = {}
        if record_type not in resolved_domains[domain]:
            resolved_domains[domain][record_type] = []
        resolved_domains[domain][record_type].append(value)


    # Write the resolved results to a file after each resolution attempt
    with open(output_results, 'a') as output_file:
        output_file.write(f"{domain}:\n")
        for record_type, values in resolved_domains[domain].items():
            for value in values:
                output_file.write(f"  {record_type}: {value}\n")

    return domain

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--source",
        type=str,
        default="",
        help="Enter the Source File",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--results-folder",
        default="results",
        help="folder for results",
    )

    parser.add_argument(
        "-n",
        "--nameservers",
        default="8.8.8.8,8.8.4.4,1.1.1.1,208.67.222.222,208.67.220.220",
        help="Custom nameservers (comma-separated)",
    )

    args = parser.parse_args()

    results_folder = args.results_folder
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)
        print(f"Created {results_folder} folder for storing results.")
    else:
        print(f"{results_folder} folder already exists.")

    # Read the source
    initial_results = args.source

    # Get the current timestamp and format it
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_results = os.path.join(results_folder, f"resolved_results_{timestamp}.txt")
    dangling_cnames_log = os.path.join(results_folder, f"dangling_cnames_{timestamp}.txt")

    custom_nameservers = args.nameservers.split(",")

    # Determine the number of threads to use
    num_threads = os.cpu_count() or 4  # Fallback to 4 if os.cpu_count() returns None
    num_threads = max(1, num_threads - 1)  # Use cores - 1 or at least 1 thread

    print(f"Using {num_threads} threads")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        with open(initial_results, 'r') as f:
            for line in f:
                futures.append(executor.submit(process_line, line, custom_nameservers, dangling_cnames_log, output_results))

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"Completed resolution for: {result}")

    print(f"All resolutions completed. Results saved to {output_results}")
    print(f"Dangling CNAMEs logged to {dangling_cnames_log}")

if __name__ == "__main__":
    main()