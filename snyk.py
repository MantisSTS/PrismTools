import requests 
import bs4
import sys


snyk_lookup_url = 'https://security.snyk.io/package/npm/{}/{}'
snyk_url = 'https://security.snyk.io/{}'

def main():
    pkg = sys.argv[1]
    ver = sys.argv[2]

    r = requests.get(snyk_lookup_url.format(pkg, ver))
    if r.status_code != 200:
        print('Error: {}'.format(r.status_code))
        sys.exit(1)

    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    vulns = soup.find_all('tr', class_='vue--table__row')
    if not vulns:
        print('No known vulnerabilities')
        sys.exit(0)

    results = []

    for vuln in vulns:
        v = vuln.find_all('a', class_='vue--anchor', href=True)
        for a in v:
            lookup_cve = requests.get(snyk_url.format(a['href'].strip()))
            if lookup_cve.status_code != 200:
                print('Error: {}'.format(lookup_cve.status_code))
                sys.exit(1)

            cve_soup = bs4.BeautifulSoup(lookup_cve.text, 'html.parser')
            cves_text = cve_soup.find_all('span', class_='cve')
            for cve in cves_text:
                if cve.text.strip() not in results:
                    pass
            
                try:
                    print(cve.find('a', href=True)['id'])
                except:
                    pass


if __name__ == '__main__':
    main()
