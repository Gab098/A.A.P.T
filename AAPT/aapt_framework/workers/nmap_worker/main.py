import pika
import os
import json
import nmap
from neo4j import GraphDatabase
import time
import logging
from flask import Flask, jsonify
import threading
import subprocess
from datetime import datetime
import uuid

# --- CONFIGURAZIONE E CONNESSIONI ---
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
NMAP_PORTS = os.getenv('NMAP_PORTS', '22,80,443,8080,3389,445,21,23,25,53,110,139,143,3306,5432,5900,8081,8443')
NMAP_TIMEOUT = os.getenv('NMAP_TIMEOUT', '30s')
NMAP_TOP_PORTS = os.getenv('NMAP_TOP_PORTS', '100')

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("nmap_worker")

# Prepara le credenziali per RabbitMQ
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
# Prepara il driver per Neo4j
try:
    db_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
except Exception as e:
    logger.error(f"Errore connessione Neo4j: {e}")
    db_driver = None

# --- HEALTHCHECK HTTP ---
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

# --- FUNZIONI DI BASE ---
def write_scan_to_db(scan_result):
    open_ports_summary = []
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return open_ports_summary
    with db_driver.session() as session:
        for host_ip, data in scan_result.items():
            session.run("MERGE (h:Host {ip: $ip}) SET h.state = $state", 
                        ip=host_ip, state=data['status']['state'])
            logger.info(f"Aggiornato Host nel DB: {host_ip} ({data['status']['state']})")
            for proto in data.get('protocols', []):
                for port_num, port_data in data.get(proto, {}).items():
                    session.run("""
                        MATCH (h:Host {ip: $ip})
                        MERGE (s:Service {name: $service_name, port: $port_num, protocol: $protocol})
                        MERGE (h)-[:RUNS_SERVICE]->(s)
                        SET s.state = $state, s.product = $product, s.version = $version, s.extrainfo = $extrainfo
                        """,
                        ip=host_ip,
                        service_name=port_data.get('name', 'unknown'),
                        port_num=port_num,
                        protocol=proto,
                        state=port_data.get('state', 'unknown'),
                        product=port_data.get('product', ''),
                        version=port_data.get('version', ''),
                        extrainfo=port_data.get('extrainfo', '')
                    )
                    logger.info(f"  -> Servizio: {port_num}/{proto} - {port_data.get('name', 'N/A')}")
                    open_ports_summary.append({
                        'ip': host_ip,
                        'port': port_num,
                        'protocol': proto,
                        'service': port_data.get('name', 'unknown'),
                        'state': port_data.get('state', 'unknown')
                    })
    return open_ports_summary

def run_nmap_task(task):
    target = task.get('target')
    ports = task.get('ports', '1-100')
    scan_type = task.get('scan_type', 'fast')
    nmap_args = task.get('nmap_args', '')
    # Costruisci comando nmap in base ai parametri
    if nmap_args:
        cmd = f"nmap {nmap_args} -p {ports} {target}"
    elif scan_type == 'full':
        cmd = f"nmap -T4 -p- {target}"
    elif scan_type == 'nse':
        cmd = f"nmap -T4 -sC -p {ports} {target}"
    else:  # fast
        cmd = f"nmap -T4 -F -p {ports} {target}"
    logging.info(f"Eseguo comando: {cmd}")
    result = subprocess.getoutput(cmd)
    # ... parsing e salvataggio risultati ...

def process_nmap_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        logger.info(f"[+] Ricevuto task Nmap: Scansione di '{target}' (task_id={task_id})")
        scan_result = run_nmap_scan(target)
        open_ports_summary = []
        status = "failure"
        summary = f"Nessun host trovato o errore di scansione su {target}."
        raw_output_path = None
        if scan_result:
            open_ports_summary = write_scan_to_db(scan_result)
            status = "success" if open_ports_summary else "failure"
            summary = (
                f"Trovate {len(open_ports_summary)} porte aperte su {target}."
                if open_ports_summary else
                f"Nessuna porta aperta trovata su {target}."
            )
            # Salva log grezzo opzionale
            raw_log_path = f"/app/logs/nmap_{task_id}.txt"
            try:
                with open(raw_log_path, "w") as f:
                    f.write(json.dumps(scan_result, indent=2))
                raw_output_path = raw_log_path
            except Exception as e:
                logger.warning(f"Impossibile salvare il log grezzo: {e}")
        result_message = {
            "task_id": task_id,
            "worker_type": "nmap_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "open_ports": [
                    {
                        "port": p["port"],
                        "protocol": p["protocol"],
                        "service": p["service"],
                        "version": p.get("version", "")
                    }
                    for p in open_ports_summary
                ]
            },
        }
        if raw_output_path:
            result_message["raw_output_path"] = raw_output_path
        try:
            channel.queue_declare(queue='results_queue', durable=True)
            channel.basic_publish(
                exchange='',
                routing_key='results_queue',
                body=json.dumps(result_message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logger.info(f"[>>>] Risultato standard pubblicato su results_queue per {target} (task_id={task_id})")
        except Exception as e:
            logger.error(f"Errore pubblicando su results_queue: {e}")
    except Exception as e:
        logger.error(f"Errore critico durante l'esecuzione del task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("[*] Task completato. In attesa del prossimo...")

def main():
    # Avvia healthcheck HTTP in thread separato
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    connection = None
    while True:
        try:
            logger.info("[*] Worker Nmap avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='nmap_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'nmap_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='nmap_tasks', on_message_callback=process_nmap_task)
            health_status["status"] = "ok"
            logger.info("[*] Inizio ad ascoltare la coda per i task...")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            health_status["status"] = "rabbitmq_error"
            logger.warning(f"[!] Errore di connessione a RabbitMQ: {e}. Riprovo tra 5 secondi...")
            time.sleep(5)
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[E] Errore non gestito: {e}")
            if connection and connection.is_open:
                connection.close()
            time.sleep(10)

if __name__ == '__main__':
    main() 