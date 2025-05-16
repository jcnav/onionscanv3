import re
import csv
import os

# Define PII patterns
patterns = {
    "Name": r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b",
    "Phone": r"\b(?:\+61|0)4\d{8}\b",
    "Email": r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
    "DOB": r"\b\d{2}/\d{2}/\d{4}\b",
    "Medicare": r"\b\d{4}\s\d{5}\s\d\b",
    "Centrelink": r"\b\d{8}[A-Z]{1}\b",
    "DriverLicence": r"\b\d{9}\b",
    "TFN": r"\b\d{3}\s\d{3}\s\d{3}\b",
    "ABN": r"\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b",
    "Address": r"\d{1,4}\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)*,\s(?:VIC|NSW|QLD|SA|WA|TAS|ACT|NT)\s\d{4}",
    "BankAcc": r"\bBSB\s\d{3}-\d{3}\sAcc\s\d{6,10}\b",
    "CardNumber": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "CCExp": r"\b\d{2}/\d{2}\b",
    "CCV": r"\b\d{3,4}\b",
    "IP": r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
}

def extract_pii_data(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"ERROR: '{input_file}' not found.")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    with open(output_file, 'w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        header = [
            "Name", "Region", "Phone", "Email", "DOB", "Medicare", "Centrelink",
            "DriverLicence", "TFN", "ABN", "Address", "BankAcc", "CardNumber",
            "CCExp", "CCV", "IP", "RawLine"
        ]
        writer.writerow(header)

        states = ["VIC", "NSW", "QLD", "SA", "WA", "TAS", "ACT", "NT"]
        for line in lines:
            for state in states:
                if state in line:
                    data = {key: (match.group() if (match := re.search(p, line)) else '') for key, p in patterns.items()}
                    row = [
                        data["Name"], state, data["Phone"], data["Email"], data["DOB"],
                        data["Medicare"], data["Centrelink"], data["DriverLicence"],
                        data["TFN"], data["ABN"], data["Address"], data["BankAcc"],
                        data["CardNumber"], data["CCExp"], data["CCV"], data["IP"],
                        line.strip().replace(",", ";")
                    ]
                    writer.writerow(row)

    print(f"Script completed. Output saved to {output_file}")

# Run the script
input_file = 'input.txt'
output_file = 'output.csv'
extract_pii_data(input_file, output_file)
