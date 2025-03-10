import re
import pandas as pd
import whois
import requests
import dns.resolver
from tqdm import tqdm
import time

def clean_domain(url):
    """Extract domain from a given URL, removing http, https, and any trailing paths."""
    domain = re.sub(r'^https?://', '', str(url)).split('/')[0]
    return domain

def get_rdap_info(domain, retries=3):
    """Fetch RDAP data for a given domain with retries."""
    rdap_url = f"https://rdap.org/domain/{domain}"
    for _ in range(retries):
        try:
            response = requests.get(rdap_url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            time.sleep(2)
    return None

def get_whois_info(domain):
    """Fetch WHOIS data for a given domain and extract relevant information."""
    try:
        w = whois.whois(domain)
        emails = list(set(email for email in w.emails if email and isinstance(email, str))) if isinstance(w.emails, list) else ([w.emails] if isinstance(w.emails, str) else [])
        nameservers = w.name_servers if hasattr(w, 'name_servers') else None
        return emails, nameservers
    except Exception:
        return None, None

def extract_abuse_email(rdap_data):
    """Extract abuse contact emails from RDAP data."""
    emails = set()
    if rdap_data and 'entities' in rdap_data:
        for entity in rdap_data['entities']:
            if 'roles' in entity and 'abuse' in entity['roles']:
                if 'vcardArray' in entity:
                    for item in entity['vcardArray'][1]:
                        if item[0] == 'email' and isinstance(item[3], str):
                            emails.add(item[3])
    return list(emails) if emails else []

def extract_nameservers(rdap_data, whois_ns):
    """Extract nameservers from RDAP data, falling back to WHOIS if necessary."""
    nameservers = []
    if rdap_data and 'nameservers' in rdap_data:
        for ns in rdap_data['nameservers']:
            if 'ldhName' in ns:
                nameservers.append(ns['ldhName'])
    if not nameservers and whois_ns:
        nameservers = whois_ns
    return nameservers if nameservers else []

def get_asn_info(ip):
    """Retrieve ASN and ISP information for a given IP address."""
    try:
        response = requests.get(f"https://api.iptoasn.com/v1/as/ip/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("as_number"), data.get("as_description")
    except Exception:
        return None, None
    return None, None

def main(csv_file):
    """Process the ICANN CSV and fetch abuse contact emails while adding ASN and ISP information."""
    df = pd.read_csv(csv_file)
    df['Registrar Abuse Email'] = None
    df['NS Abuse Contacts'] = None
    df['MX Abuse Contacts'] = None
    df['IP Abuse Contacts'] = None
    df['ASN Abuse Contacts'] = None
    df['CDN Abuse Contacts'] = None
    df['ASN Number'] = None
    df['ISP Provider'] = None
    
    for index, row in tqdm(df.iterrows(), total=df.shape[0]):
        domain = clean_domain(row['Link'])
        
        # Perform a single RDAP and WHOIS lookup per domain
        rdap_data = get_rdap_info(domain)
        whois_emails, whois_nameservers = get_whois_info(domain)
        
        # Extract Abuse Emails
        registrar_abuse_contacts = extract_abuse_email(rdap_data) + whois_emails
        df.at[index, 'Registrar Abuse Email'] = ', '.join(filter(None, registrar_abuse_contacts)) if registrar_abuse_contacts else None
        
        # Extract Nameservers (RDAP preferred, fallback to WHOIS)
        nameservers = extract_nameservers(rdap_data, whois_nameservers)
        
        # Extract NS Abuse Contacts
        ns_abuse_contacts = extract_abuse_email(rdap_data) + whois_emails
        df.at[index, 'NS Abuse Contacts'] = ', '.join(filter(None, ns_abuse_contacts)) if ns_abuse_contacts else None
        
        # Extract MX Servers
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange).rstrip('.') for r in mx_answers]
        except Exception:
            mx_records = None
        
        # Extract MX Abuse Contacts
        mx_abuse_contacts = extract_abuse_email(rdap_data) + whois_emails
        df.at[index, 'MX Abuse Contacts'] = ', '.join(filter(None, mx_abuse_contacts)) if mx_abuse_contacts else None
        
        # Extract IP Address
        try:
            ip_answers = dns.resolver.resolve(domain, 'A')
            ip_address = ip_answers[0].to_text() if ip_answers else None
        except Exception:
            ip_address = None
        
        # Extract ASN & ISP Information
        if ip_address:
            asn_number, isp_provider = get_asn_info(ip_address)
            df.at[index, 'ASN Number'] = asn_number if asn_number else None
            df.at[index, 'ISP Provider'] = isp_provider if isp_provider else None
        
    output_file = "icann_abuse_contacts_cleaned.csv"
    df.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}")

if __name__ == "__main__":
    input_csv = "<YOUR CSV HERE>"
    main(input_csv)
