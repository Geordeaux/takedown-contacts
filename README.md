# ICANN Abuse Contacts Lookup Script

## Overview
This Python script processes a CSV file containing ICANN-accredited registrars and their domain links. It extracts and retrieves relevant **abuse contact emails** for different infrastructure providers using **RDAP, WHOIS, and DNS lookups**. Additionally, it collects **ASN, ISP, and hosting provider details** for better abuse reporting.

## Features
- **Extracts abuse contacts from multiple sources:**
  - **Registrar Abuse Email** (Domain Registrar)
  - **NS Abuse Contacts** (Nameserver Provider)
  - **MX Abuse Contacts** (Mail Server Provider)
  - **IP Abuse Contacts** (Hosting Provider)
  - **ASN Abuse Contacts** (ISP/Network Provider)
  - **CDN Abuse Contacts** (Cloudflare, Akamai, etc.)
- **Performs RDAP and WHOIS lookups** to gather abuse contact emails.
- **Resolves domain A records** to get the hosting IP address.
- **Queries ASN databases** to determine the ISP and hosting provider.
- **Deduplicates email addresses** to ensure efficient reporting.
- **Processes a CSV file and exports results to a cleaned CSV.**

## Dependencies
Ensure you have the following Python libraries installed:
```
pip install pandas tqdm python-whois requests dnspython
```

## How to use
1. Prepare the Input CSV
Ensure your CSV file has a column named Link, which contains domain URLs.

Example format:
```
Name, IANA ID, Country, Contact Info, Link
Example Registrar, 146, US, contact@example.com, https://example.com
```

You can also just export a master list of registrars from ICANN here:
https://www.icann.org/en/accredited-registrars

2. Add the cvs file name tot he bottom of the python script in the `<YOUR CSV FILE>` section

3. Run the Script
```
python3 abuse-contacts.py
```
The script will process the CSV, perform lookups, and generate a cleaned CSV file.

4. Output File
The script will generate icann_abuse_contacts_cleaned.csv, containing:
- Registrar, NS, MX, IP, ASN, and CDN abuse contacts.
- ASN number and ISP provider for the domain’s IP address.

## Additional Notes
The script uses RDAP and WHOIS for querying abuse contacts.
ASN & ISP details are fetched from IP-to-ASN lookup APIs.
The script automatically removes duplicate abuse contacts for better clarity.

## Future Enhancements
Automated Abuse Reporting: Sending abuse reports via email.
Enhanced Threat Intelligence: Flagging suspicious registrars based on historical abuse.
