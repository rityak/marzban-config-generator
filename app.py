import logging
from flask import Flask, request, jsonify, render_template
import ipaddress
import threading
import time
import dns.resolver
import dns.reversename
import re
import requests
import random
import subprocess
import json

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)

def get_http_response_time(url):
    try:
        logging.debug(f"Sending HTTP GET request to: {url}")
        start_time = time.time()
        response = requests.get(url, timeout=5)
        elapsed_time = (time.time() - start_time) * 1000  # Преобразуем в миллисекунды
        if response.status_code == 200:
            logging.debug(f"Received 200 OK from {url} in {elapsed_time:.2f} ms")
            return elapsed_time
        else:
            logging.debug(f"Received status code {response.status_code} from {url}")
            return None
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP request to {url} failed: {e}")
        return None

def get_domains_from_ip(ip_str):
    try:
        logging.debug(f"Resolving PTR records for IP: {ip_str}")
        # Используем dnspython для получения PTR записей
        rev_name = dns.reversename.from_address(ip_str)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        hostnames = [str(rdata.target).rstrip('.') for rdata in answers]
        logging.debug(f"Found PTR records for {ip_str}: {hostnames}")
        return hostnames
    except Exception as e:
        logging.debug(f"No PTR records found for {ip_str}: {e}")
        return []

def get_domains_and_measure_response(ip_str, domain_response_times, lock, success_counter, max_success, stop_event):
    if stop_event.is_set():
        return
    hostnames = get_domains_from_ip(ip_str)
    # Исключаем домены, соответствующие *.aeza.network
    filtered_hostnames = [domain for domain in hostnames if not re.match(r'.*\.aeza\.network$', domain)]
    logging.debug(f"Filtered hostnames for {ip_str}: {filtered_hostnames}")
    for domain_name in filtered_hostnames:
        if stop_event.is_set():
            break
        if domain_name:
            url = f"http://{domain_name}"
            response_time = get_http_response_time(url)
            if response_time is not None:
                with lock:
                    if domain_name not in domain_response_times:
                        domain_response_times[domain_name] = response_time
                        success_counter[0] += 1
                        logging.debug(f"Found {success_counter[0]} successful results")
                        if success_counter[0] >= max_success:
                            stop_event.set()
                            logging.debug(f"Reached maximum of {max_success} successful results.")
                if stop_event.is_set():
                    break
            # Пауза, чтобы избежать бана
            time.sleep(1)  # Пауза в 1 секунду между запросами

def generate_private_key():
    try:
        logging.debug("Generating private key using xray x25519")
        result = subprocess.run(['docker', 'exec', 'marzban-marzban-1', 'xray', 'x25519'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout
            private_key_line = [line for line in output.split('\n') if 'Private key:' in line]
            if private_key_line:
                private_key = private_key_line[0].split('Private key:')[-1].strip()
                logging.debug(f"Generated private key: {private_key}")
                return private_key
            else:
                logging.error("Private key not found in command output")
                return "Ошибка при получении privateKey"
        else:
            logging.error(f"Command failed with error: {result.stderr}")
            return "Ошибка при выполнении команды для privateKey"
    except Exception as e:
        logging.exception(f"Exception during private key generation: {e}")
        return "Ошибка при генерации privateKey"

def generate_short_id():
    try:
        logging.debug("Generating short ID using openssl rand -hex 8")
        result = subprocess.run(['openssl', 'rand', '-hex', '8'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            short_id = result.stdout.strip()
            logging.debug(f"Generated short ID: {short_id}")
            return short_id
        else:
            logging.error(f"Command failed with error: {result.stderr}")
            return "Ошибка при получении shortIds"
    except Exception as e:
        logging.exception(f"Exception during short ID generation: {e}")
        return "Ошибка при генерации shortIds"

def generate_config(best_domain, private_key, short_id):
    # Выбираем случайный порт из непопулярных (например, диапазон 30000-40000)
    port = random.randint(30000, 40000)
    config = {
        "log": {
            "loglevel": "warning"
        },
        "routing": {
            "rules": [
                {
                    "ip": [
                    "geoip:private"
                    ],
                    "outboundTag": "BLOCK",
                    "type": "field"
                }
            ]
        },
        "inbounds": [
            {
                "tag": "Shadowsocks TCP",
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "shadowsocks",
                "settings": {
                    "clients": [],
                    "network": "tcp,udp"
                }
            },{
                "tag": "VLESS + TCP + REALITY",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "tcpSettings": {},
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": f"{best_domain}:443" if best_domain else "Ошибка: домен не найден",
                        "xver": 0,
                        "serverNames": [
                            best_domain if best_domain else "Ошибка: домен не найден"
                        ],
                        "privateKey": private_key if private_key else "Ошибка: privateKey не найден",
                        "shortIds": [
                            short_id if short_id else "Ошибка: shortIds не найден"
                        ]
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "blackhole",
                "tag": "BLOCK"
            },
            {
                "outboundTag": "DIRECT",
                "domain": [
                    "full:cp.cloudflare.com",
                    "domain:msftconnecttest.com",
                    "domain:msftncsi.com",
                    "domain:connectivitycheck.gstatic.com",
                    "domain:captive.apple.com",
                    "full:detectportal.firefox.com",
                    "domain:networkcheck.kde.org",
                    "full:*.gstatic.com"
                ],
                "type": "field"
            }
        ]
    }
    return config

@app.route('/<ip_address>', methods=['GET'])
def index(ip_address):
    logging.info(f"Received request for IP address: {ip_address}")
    # Отображаем HTML-страницу с прелоадером
    return render_template('index.html', ip_address=ip_address)

@app.route('/api/process_ip', methods=['GET'])
def process_ip():
    ip_address = request.args.get('ip')
    logging.info(f"Processing IP address: {ip_address}")
    try:
        # Проверяем корректность IP адреса
        ip = ipaddress.ip_address(ip_address)
        
        # Определяем подсеть /24
        network = ipaddress.ip_network(f"{ip_address}/24", strict=False)
        logging.debug(f"Calculated network: {network}")
        
        domain_response_times = {}
        lock = threading.Lock()
        threads = []
        success_counter = [0]  # Используем список для возможности изменения в потоках
        max_success = 5
        stop_event = threading.Event()
        
        for ip_addr in network.hosts():
            if stop_event.is_set():
                break
            ip_str = str(ip_addr)
            t = threading.Thread(target=get_domains_and_measure_response, args=(ip_str, domain_response_times, lock, success_counter, max_success, stop_event))
            t.start()
            threads.append(t)
            # Пауза между запуском потоков
            time.sleep(0.1)  # Отрегулируйте время паузы по необходимости
        
        for t in threads:
            t.join()
        
        if not domain_response_times:
            logging.warning("No domain response times collected")
            best_domain = None
        else:
            # Находим домен с наименьшим временем отклика
            best_domain = min(domain_response_times, key=domain_response_times.get)
            logging.info(f"Best domain: {best_domain} with response time {domain_response_times[best_domain]:.2f} ms")
        
        # Генерируем privateKey и shortIds
        private_key = generate_private_key()
        short_id = generate_short_id()
        
        # Генерируем конфиг
        config = generate_config(best_domain, private_key, short_id)
        
        # Возвращаем конфиг в виде JSON
        return jsonify(config)
        
    except ValueError as e:
        logging.error(f"Invalid IP address provided: {ip_address}")
        return jsonify({"error": "Неверный IP адрес"}), 400
    except Exception as e:
        logging.exception(f"Exception during processing IP address {ip_address}: {e}")
        return jsonify({"error": "Произошла ошибка при обработке IP адреса"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
