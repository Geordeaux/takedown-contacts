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
    """Fetch WHOIS data for a given domain."""
    try:
        w = whois.whois(domain)
        if hasattr(w, 'emails'):
            return list(set(email for email in w.emails if email and isinstance(email, str))) if isinstance(w.emails, list) else [w.emails]
    except Exception:
        return None
    return None

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
    return list(emails) if emails else None

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

def get_abuse_emails_for_domains(domains):
    """Retrieve abuse contact emails for a list of domains via RDAP and WHOIS, ensuring deduplication."""
    abuse_contacts = set()
    for domain in domains:
        rdap_data = get_rdap_info(domain)
        if rdap_data:
            abuse_contacts.update(extract_abuse_email(rdap_data) or [])
        
        whois_emails = get_whois_info(domain)
        if whois_emails:
            abuse_contacts.update(whois_emails)
    return list(abuse_contacts) if abuse_contacts else None

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
    
    seen_emails = {
        'Registrar': set(),
        'NS': set(),
        'MX': set(),
        'IP': set(),
        'ASN': set(),
        'CDN': set()
    }
    
    for index, row in tqdm(df.iterrows(), total=df.shape[0]):
        domain = clean_domain(row['Link'])
        
        # Fetch RDAP & WHOIS Data
        registrar_abuse_contacts = get_abuse_emails_for_domains([domain])
        if registrar_abuse_contacts:
            unique_contacts = [email for email in registrar_abuse_contacts if email and email not in seen_emails['Registrar']]
            seen_emails['Registrar'].update(unique_contacts)
            df.at[index, 'Registrar Abuse Email'] = ', '.join(unique_contacts) if unique_contacts else None
        
        # Extract NS Abuse Contacts
        ns_abuse_contacts = get_abuse_emails_for_domains([domain])
        if ns_abuse_contacts:
            unique_contacts = [email for email in ns_abuse_contacts if email and email not in seen_emails['NS']]
            seen_emails['NS'].update(unique_contacts)
            df.at[index, 'NS Abuse Contacts'] = ', '.join(unique_contacts) if unique_contacts else None
        
        # Extract MX Abuse Contacts
        mx_abuse_contacts = get_abuse_emails_for_domains([domain])
        if mx_abuse_contacts:
            unique_contacts = [email for email in mx_abuse_contacts if email and email not in seen_emails['MX']]
            seen_emails['MX'].update(unique_contacts)
            df.at[index, 'MX Abuse Contacts'] = ', '.join(unique_contacts) if unique_contacts else None
        
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
