import requests
import validators
from main import check_email_record


def update_list():
    with open("disposable_domains.txt", "r") as disposable_domains:
        disposable_domains = disposable_domains.read().splitlines()
        print(f"Loaded {len(disposable_domains)} disposable domains from your previous run.")

        with open('sources.txt', 'r') as sources:
            source_list = sources.readlines()
        print(f"Found {len(source_list)} sources")

        # Combine domains from the source lists
        combined_content = ''
        for source in source_list:
            source = source.strip()
            response = requests.get(source)
            if response.status_code == 200:
                print(f"List contains lines: {len(response.text.splitlines())}")
                combined_content += response.text
            else:
                print(f"{source} could not be accessed")
                exit(1)
        print(f"Total lines: {len(combined_content.splitlines())}")
        combined_list = combined_content.splitlines()
        combined_list_cleaned = []

        for line in combined_list:
            line = line.replace('\n', '').replace('"', '').replace(',', '').strip()
            if line and line not in (combined_list_cleaned or disposable_domains) and validators.domain(line):
                combined_list_cleaned.append(line)
        print(f"Total lines after cleaning: {len(combined_list_cleaned)}")

        with open('domains_staged.txt', 'w') as combined_list_file:
            for line in combined_list_cleaned:
                combined_list_file.write(f"{line}\n")
        print(f"Saved {len(combined_list_cleaned)} lines to domains_staged.txt")

        # Check if the domains have MX records
        combined_list_with_mx = []
        combine_list_without_mx = []
        count = 0
        total_cleaned = len(combined_list_cleaned)

        for domain in combined_list_cleaned:
            print(f"Checking {count} out of {total_cleaned} domains. Percentage complete: {round(count/total_cleaned*100, 2)}%")
            if has_mx_record(domain):
                combined_list_with_mx.append(domain)
            else:
                combine_list_without_mx.append(domain)
            count += 1

        with open('disposable_domains.txt', 'w') as disposable_domains_file:
            for line in combine_list_without_mx:
                disposable_domains_file.write(f"{line}\n")
        print(f"Saved {len(combine_list_without_mx)} lines to disposable_domains.txt")


def has_mx_record(domain):
    email = "hello@" + domain
    valid_mx = check_email_record(email, True, True)

    return valid_mx


update_list()
