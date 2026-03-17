eventos = [
    {"ip": "192.168.0.10", "evento": "login_sucesso"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "10.0.0.5", "evento": "scan_porta"},
    {"ip": "10.0.0.5", "evento": "scan_porta"},
    {"ip": "172.16.0.7", "evento": "login_sucesso"},
    {"ip": "8.8.8.8", "evento": "acesso_externo"},
]


def contar_eventos(lista_eventos):
    contagem = {}

    for item in lista_eventos:
        tipo = item["evento"]

        if tipo in contagem:
            contagem[tipo] += 1
        else:
            contagem[tipo] = 1

    return contagem


def identificar_bruteforce(lista_eventos):
    falhas = {}

    for item in lista_eventos:
        if item["evento"] == "login_falha":
            ip = item["ip"]

            if ip in falhas:
                falhas[ip] += 1
            else:
                falhas[ip] = 1

    suspeitos = []

    for ip in falhas:
        if falhas[ip] >= 3:
            suspeitos.append(ip)

    return suspeitos


def identificar_scanners(lista_eventos):
    scans = {}

    for item in lista_eventos:
        if item["evento"] == "scan_porta":
            ip = item["ip"]

            if ip in scans:
                scans[ip] += 1
            else:
                scans[ip] = 1

    scanners = []

    for ip in scans:
        if scans[ip] >= 2:
            scanners.append(ip)

    return scanners


def listar_ips_unicos(lista_eventos):
    ips = []

    for item in lista_eventos:
        ip = item["ip"]

        if ip not in ips:
            ips.append(ip)

    return ips


def gerar_relatorio(lista_eventos):

    print("=== MINI SOC ANALYZER ===\n")

    print("Total de eventos analisados:", len(lista_eventos), "\n")

    print("Resumo por tipo:")

    resumo = contar_eventos(lista_eventos)

    for evento in resumo:
        print(evento + ":", resumo[evento])

    print("\nIPs únicos monitorados:")

    ips = listar_ips_unicos(lista_eventos)

    for ip in ips:
        print(ip)

    print("\nPossível brute force:")

    bruteforce = identificar_bruteforce(lista_eventos)

    for ip in bruteforce:
        print(ip)

    print("\nPossível scanner:")

    scanners = identificar_scanners(lista_eventos)

    for ip in scanners:
        print(ip)


if __name__ == "__main__":
    gerar_relatorio(eventos)