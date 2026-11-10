import requests

URL_IPINFO = 'http://ipinfo.io'
def get_location(ip):
    response= requests.get(URL_IPINFO + "/" + ip+'/json')
    if response.status_code == 200:
        return response.json()


def get_country(ip):
    """
    in: une adresse ip
    out: code pays (ex: 'FR') ou 'Inconnu' si ipinfo ne répond pas
    """
    try:
        location = get_location(ip)
    except requests.RequestException as e:
        print(ip + ' error : ' + str(e))
        return 'Inconnu'
    if location and 'country' in location:
        return location['country']
    return 'Inconnu'


def count_by_country(ip_counts):
    """
    in: dictionnaire {ip: nombre d'échecs}
    out: dictionnaire {pays: nombre d'échecs}
    """
    pays_des_ip = {}   # mémoire : chaque ip n'est demandée qu'une seule fois à ipinfo
    resultat = {}
    total = len(ip_counts)
    for i, ip in enumerate(ip_counts, start=1):
        if ip not in pays_des_ip:
            pays_des_ip[ip] = get_country(ip)
        pays = pays_des_ip[ip]
        resultat[pays] = resultat.get(pays, 0) + ip_counts[ip]
        if i % 100 == 0:
            print(f'  {i}/{total} adresses ip traitées...')
    return resultat

if __name__ == "__main__":
    print(get_location('176.32.193.16'))
    print(get_country('176.32.193.16'))