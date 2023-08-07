import requests
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def test_sql_injection_vulnerability(url):
    # Injection SQL malveillante
    payload = "' OR 1=1 --"
    target_url = url + f"?id={payload}"
    
    response = requests.get(target_url)
    
    if "error" in response.text.lower():
        print("Vulnérabilité d'injection SQL détectée.")
    else:
        print("Le site n'est pas vulnérable à l'injection SQL.")

# Exemple d'utilisation avec votre propre URL
url = "https://www.mysite.fr/"
test_sql_injection_vulnerability(url)


def check_vulnerable_headers(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get(url, headers=headers)

    # Vérifier les en-têtes pour des vulnérabilités connues
    print("\nRésultats du scan pour les en-têtes :")
    if 'Server' in response.headers:
        print(f'En-tête Server : {response.headers["Server"]}')
        if 'Apache' in response.headers['Server']:
            print('Le serveur est Apache. Vérifiez la version pour les vulnérabilités connues.')
    if 'X-Powered-By' in response.headers:
        print(f'En-tête X-Powered-By : {response.headers["X-Powered-By"]}')
        if 'PHP' in response.headers['X-Powered-By']:
            print('Le site est propulsé par PHP. Vérifiez la version pour les vulnérabilités connues.')
    if 'X-AspNet-Version' in response.headers:
        print(f'En-tête X-AspNet-Version : {response.headers["X-AspNet-Version"]}')
        print('ASP.NET est utilisé. Vérifiez la version pour les vulnérabilités connues.')
    if 'X-Frame-Options' in response.headers:
        print(f'En-tête X-Frame-Options : {response.headers["X-Frame-Options"]}')
        if response.headers['X-Frame-Options'] != 'SAMEORIGIN':
            print('Attention : X-Frame-Options n\'est pas correctement configuré. Cela pourrait rendre le site vulnérable à une attaque de clickjacking.')

def check_ssl_vulnerabilities(url):
    print("\nRésultats du scan pour les vulnérabilités SSL/TLS :")
    try:
        # Activation de la vérification des certificats SSL/TLS
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            print("Le site prend en charge HTTPS.")
            # Vérification de la vulnérabilité SSL/TLS ici, par exemple :
            if "TLSv1" in response.text:
                print("Le site utilise une version obsolète du protocole TLS (TLSv1).")
        else:
            print("Le site ne répond pas avec le code d'état 200.")
    except requests.exceptions.SSLError as e:
        print(f"Le site présente des problèmes de certificat SSL : {e}")
        print("Not OK - Problème de certificat SSL")

def check_sql_injection_vulnerability_advanced(url):
    payloads = ["1' OR '1'='1", "1' OR 1=1 --", "' UNION SELECT username, password FROM users --"]
    print("\nRésultats du scan pour les vulnérabilités d'injection SQL :")
    for payload in payloads:
        test_url = url + "?id=" + payload
        response = requests.get(test_url)

        if "Error in SQL syntax" in response.text:
            print(f"Vulnérabilité d'injection SQL détectée avec la charge utile : {payload}")
            print("Not OK - Vulnérabilité d'injection SQL détectée")

def check_xss_vulnerability_advanced(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    print("\nRésultats du scan pour les vulnérabilités XSS :")
    for form in forms:
        form_action = form.get('action', '')
        form_inputs = form.find_all('input')
        for form_input in form_inputs:
            input_name = form_input.get('name', '')
            if input_name:
                payload = f"<script>alert('XSS Vulnerability')</script>"
                data = {input_name: payload}
                response = requests.post(url + form_action, data=data)

                if payload in response.text:
                    print(f"Vulnérabilité XSS détectée dans le formulaire : {form_action} - champ : {input_name}")
                    print("Not OK - Vulnérabilité XSS détectée")

def check_security_headers(url):
    security_headers = {
        'Content-Security-Policy': '',
        'X-XSS-Protection': '',
        'X-Content-Type-Options': ''
    }
    response = requests.get(url)

    print("\nRésultats du scan pour les en-têtes de sécurité :")
    for header, value in security_headers.items():
        if header in response.headers:
            print(f'En-tête {header} : {response.headers[header]}')
        else:
            print(f'En-tête {header} non défini.')

def check_weak_passwords(url):
    # Code pour vérifier les mots de passe faibles ou courants utilisés sur le site
    print("\nVérification des mots de passe faibles :")
    # Ajoutez votre code pour la vérification des mots de passe ici

def check_api_security(url):
    # Code pour vérifier la sécurité des API
    print("\nVérification de la sécurité des API :")
    # Ajoutez votre code pour la vérification de la sécurité des API ici

def check_ddos_vulnerability(url):
    # Code pour vérifier les vulnérabilités de déni de service (DDoS)
    print("\nVérification des vulnérabilités de déni de service (DDoS) :")
    # Ajoutez votre code pour la vérification des vulnérabilités DDoS ici

def check_file_upload_security(url):
    # Code pour vérifier les vulnérabilités de sécurité des fichiers téléchargés
    print("\nVérification des vulnérabilités de sécurité des fichiers téléchargés :")
    # Ajoutez votre code pour la vérification des vulnérabilités de sécurité des fichiers téléchargés ici

def check_cookie_security(url):
    # Code pour vérifier les vulnérabilités de sécurité des cookies
    print("\nVérification des vulnérabilités de sécurité des cookies :")
    # Ajoutez votre code pour la vérification des vulnérabilités de sécurité des cookies ici

def check_email_security(url):
    # Code pour vérifier les vulnérabilités de sécurité des e-mails
    print("\nVérification des vulnérabilités de sécurité des e-mails :")
    # Ajoutez votre code pour la vérification des vulnérabilités de sécurité des e-mails ici

def check_robots_sitemap_security(url):
    # Code pour vérifier les vulnérabilités de sécurité des fichiers robots.txt et sitemap.xml
    print("\nVérification des vulnérabilités de sécurité des fichiers robots.txt et sitemap.xml :")
    # Ajoutez votre code pour la vérification des vulnérabilités de sécurité des fichiers robots.txt et sitemap.xml ici

def check_database_security(url):
    # Code pour vérifier la sécurité des bases de données
    print("\nVérification de la sécurité des bases de données :")
    # Ajoutez votre code pour la vérification de la sécurité des bases de données ici

def check_compliance_standards(url):
    # Code pour vérifier la conformité aux normes de sécurité
    print("\nVérification de la conformité aux normes de sécurité :")
    # Ajoutez votre code pour la vérification de la conformité aux normes de sécurité ici

def check_server_security(url):
    # Code pour vérifier les vulnérabilités de sécurité des serveurs
    print("\nVérification des vulnérabilités de sécurité des serveurs :")
    # Ajoutez votre code pour la vérification des vulnérabilités de sécurité des serveurs ici
    
def check_js_security(url):
    print("\nVérification des vulnérabilités de sécurité dans les fichiers JavaScript :")
    response = requests.get(url)
    js_files = [js_file['src'] for js_file in BeautifulSoup(response.text, 'html.parser').find_all('script', src=True)]
    for js_file in js_files:
        js_url = urljoin(url, js_file)
        js_response = requests.get(js_url)
        # Vérification des vulnérabilités de sécurité dans le fichier JavaScript
        if "alert(" in js_response.text:
            print(f"Vulnérabilité détectée dans le fichier JavaScript : {js_url}")
            print("Not OK - Vulnérabilité dans les fichiers JavaScript détectée")


def check_css_security(url):
    print("\nVérification des vulnérabilités de sécurité dans les fichiers CSS :")
    response = requests.get(url)
    css_files = [css_file['href'] for css_file in BeautifulSoup(response.text, 'html.parser').find_all('link', rel='stylesheet')]
    for css_file in css_files:
        if css_file.startswith(('http:', 'https:')):
            css_url = css_file
        else:
            css_url = urljoin(url, css_file)
        css_response = requests.get(css_url)
        # Vérification des vulnérabilités de sécurité dans le fichier CSS
        if "expression(" in css_response.text:
            print(f"Vulnérabilité détectée dans le fichier CSS : {css_url}")
            print("Not OK - Vulnérabilité dans les fichiers CSS détectée")
            

def check_csp_security(url):
    print("\nVérification des vulnérabilités de sécurité dans les en-têtes CSP :")
    response = requests.get(url)
    csp_header = response.headers.get('Content-Security-Policy', '')
    if not csp_header:
        print("En-tête CSP non défini. Il est recommandé de configurer un en-tête CSP pour renforcer la sécurité.")
        return

    # Vérification des vulnérabilités dans l'en-tête CSP
    if 'unsafe-inline' in csp_header:
        print("En-tête CSP contient 'unsafe-inline'. Cela peut rendre le site vulnérable aux attaques XSS.")
    if 'unsafe-eval' in csp_header:
        print("En-tête CSP contient 'unsafe-eval'. Cela peut rendre le site vulnérable aux attaques d'injection de code.")
    # Ajoutez d'autres vérifications de vulnérabilités CSP si nécessaire

def check_hpkp_security(url):
    print("\nVérification des vulnérabilités de sécurité HPKP :")
    response = requests.get(url)
    hpkp_header = response.headers.get('Public-Key-Pins', '')
    if not hpkp_header:
        print("En-tête HPKP non défini. Il est recommandé de configurer un en-tête HPKP pour renforcer la sécurité.")
        return

    # Vérification des vulnérabilités dans l'en-tête HPKP
    if 'max-age=0' in hpkp_header:
        print("En-tête HPKP a une durée de validité 'max-age=0'. Cela peut entraîner des problèmes de sécurité.")
    # Ajoutez d'autres vérifications de vulnérabilités HPKP si nécessaire

def check_server_configuration(url):
    print("\nVérification des erreurs de configuration du serveur :")
    # Ajoutez votre code pour vérifier les erreurs de configuration du serveur ici


def check_secure_cookies(url):
    print("\nVérification de la présence de cookies sécurisés et HTTPOnly :")
    response = requests.get(url)
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure:
            print(f"Le cookie {cookie.name} n'est pas sécurisé (Secure).")
        if not cookie.has_nonstandard_attr('HttpOnly'):
            print(f"Le cookie {cookie.name} n'est pas défini comme HTTPOnly.")

def check_hsts_security(url):
    print("\nVérification des vulnérabilités de sécurité dans les en-têtes HSTS :")
    response = requests.get(url)
    hsts_header = response.headers.get('Strict-Transport-Security', '')
    if not hsts_header:
        print("En-tête HSTS non défini. Il est recommandé de configurer un en-tête HSTS pour renforcer la sécurité.")
        return

    # Vérification des vulnérabilités dans l'en-tête HSTS
    if 'max-age=0' in hsts_header:
        print("En-tête HSTS a une durée de validité 'max-age=0'. Cela peut entraîner des problèmes de sécurité.")


def check_csrf_vulnerabilities(url):
    print("\nVérification des vulnérabilités CSRF :")
    response = requests.get(url)
    forms = BeautifulSoup(response.text, 'html.parser').find_all('form')
    for form in forms:
        csrf_token = form.find('input', {'name': 'csrf_token'})
        if not csrf_token:
            print(f"Vulnérabilité CSRF détectée dans le formulaire : {form}")
            print("Not OK - Vulnérabilité CSRF détectée")


def check_pci_dss_compliance(url):
    payment_page_url = 'https://revuecharles.fr/commande/'
    response = requests.get(payment_page_url, verify=True)
    if response.status_code == 200:
        print('La page de paiement est accessible.')
        if response.url.startswith('https://'):
            print('La page de paiement utilise HTTPS.')
            # Vérification du certificat SSL/TLS ici
            if is_valid_ssl_certificate(response):
                print('Le certificat SSL/TLS est valide.')
                # Autres vérifications spécifiques PCI DSS que vous pouvez ajouter ici
            else:
                print('Le certificat SSL/TLS n\'est pas valide. Cela peut ne pas être conforme à PCI DSS.')
        else:
            print('La page de paiement n\'utilise pas HTTPS. Cela peut ne pas être conforme à PCI DSS.')
    else:
        print('La page de paiement n\'est pas accessible.')
        print('Cela peut ne pas être conforme à PCI DSS.')

def is_valid_ssl_certificate(response):
    # Implémentez la vérification du certificat SSL/TLS ici
    # Vous pouvez utiliser la bibliothèque ssl pour effectuer des vérifications plus poussées sur le certificat.
    # Par exemple, vous pouvez vérifier la validité de la date d'expiration, la chaîne de certificats, etc.
    # Retournez True si le certificat est valide, False sinon.
    pass

def security_audit(url):
    print(f"\nCommence l'audit de sécurité pour {url}...")
    status = "OK"  # Variable de statut, initialement définie à "OK"

    check_vulnerable_headers(url)
    check_ssl_vulnerabilities(url)
    check_sql_injection_vulnerability_advanced(url)
    check_xss_vulnerability_advanced(url)
    check_security_headers(url)
    check_weak_passwords(url)
    check_api_security(url)
    check_ddos_vulnerability(url)
    check_file_upload_security(url)
    check_cookie_security(url)
    check_email_security(url)
    check_robots_sitemap_security(url)
    check_database_security(url)
    check_compliance_standards(url)
    check_server_security(url)
    check_js_security(url)
    check_csp_security(url)
    check_hpkp_security(url)
    check_server_configuration(url)
    check_css_security(url)
    check_secure_cookies(url)
    check_hsts_security(url)
    check_csrf_vulnerabilities(url)

    # Si une vulnérabilité est détectée, mettez le statut à "Not OK"
    if "Not OK" in [output for output in dir() if "Not OK" in output]:
        status = "Not OK"

    print(f"\nAudit de sécurité pour {url} terminé.")
    return status

if __name__ == "__main__":
    target_url = "https://www.smysite.fr/"  # Remplacez par l'URL cible

    scan_status = security_audit(target_url)
    print(f"\nStatut du scan : {scan_status}")
    

