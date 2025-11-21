import whois
import json
import datetime

def test_domain(domain):
    print(f"Testing domain: {domain}")
    try:
        w = whois.whois(domain)
        print(f"Result type: {type(w)}")
        print(f"Raw keys: {list(w.keys())}")
        print(f"domain_name: {w.get('domain_name')}")
        print(f"registrar: {w.get('registrar')}")
    except Exception as e:
        print(f"Error: {e}")
    print("-" * 20)

if __name__ == "__main__":
    test_domain("www.bennett.edu.in")
    test_domain("bennett.edu.in")
    test_domain("google.com")
