import pika
import json
import logging
import subprocess
import os
import uuid
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'guest')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'guest')

QUEUE = 'privesc_tasks'

# Connessione RabbitMQ
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials, heartbeat=600)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()
channel.queue_declare(queue=QUEUE, durable=True)

logging.info('privesc_worker in ascolto su coda privesc_tasks...')

def run_privesc_task(task):
    shell_id = task.get('shell_id')
    script = task.get('script', 'linpeas')  # linpeas o winPEAS
    # In un sistema reale, qui dovresti collegarti alla shell remota (SSH, Meterpreter, ecc.)
    # Qui simulo solo l'esecuzione locale per demo
    if script == 'linpeas':
        cmd = ["/app/linpeas.sh"]
    elif script == 'winPEAS':
        cmd = ["/app/winPEAS.bat"]
    else:
        logging.error(f"Script privesc non riconosciuto: {script}")
        return
    logging.info(f"Eseguo {script} su shell_id {shell_id} (simulato)")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        logging.info(f"Output {script} (troncato):\n{result.stdout[:1000]}")
        # Qui puoi aggiungere parsing output e invio risultati a Neo4j o RabbitMQ
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout esecuzione {script}")
    except Exception as e:
        logging.error(f"Errore esecuzione {script}: {e}")

def callback(ch, method, properties, body):
    try:
        task = json.loads(body)
        task_id = task.get('task_id') or str(uuid.uuid4())
        shell_id = task.get('shell_id')
        script = task.get('script', 'linpeas')
        target = task.get('target')
        logging.info(f"Ricevuto task privesc: {task} (task_id={task_id})")
        findings = []
        status = "failure"
        summary = f"Nessun risultato da {script} su {target}."
        raw_output_path = None
        # Esegui lo script e salva output
        if script == 'linpeas':
            cmd = ["/app/linpeas.sh"]
        elif script == 'winPEAS':
            cmd = ["/app/winPEAS.bat"]
        else:
            logging.error(f"Script privesc non riconosciuto: {script}")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout
            # Parsing demo: cerca stringhe indicative (da migliorare)
            for line in output.splitlines():
                if "SUID" in line or "GTFOBins" in line:
                    findings.append({"type": "suid_binary", "description": line, "exploit_suggestion": "GTFOBins"})
                if "/etc/passwd" in line:
                    findings.append({"type": "writable_file", "description": "/etc/passwd"})
            status = "success" if findings else "failure"
            summary = (
                f"Trovati {len(findings)} possibili vettori di privesc su {target}."
                if findings else
                f"Nessun vettore di privesc trovato su {target}."
            )
            # Salva log grezzo opzionale
            raw_log_path = f"/app/logs/privesc_{task_id}.txt"
            try:
                with open(raw_log_path, "w") as f:
                    f.write(output)
                raw_output_path = raw_log_path
            except Exception as e:
                logging.warning(f"Impossibile salvare il log grezzo: {e}")
        except subprocess.TimeoutExpired:
            output = "Timeout esecuzione privesc"
        except Exception as e:
            output = f"Errore esecuzione {script}: {e}"
        result_message = {
            "task_id": task_id,
            "worker_type": "privesc_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "script_used": script,
                "findings": findings
            },
        }
        if raw_output_path:
            result_message["raw_output_path"] = raw_output_path
        try:
            ch.queue_declare(queue='results_queue', durable=True)
            ch.basic_publish(
                exchange='',
                routing_key='results_queue',
                body=json.dumps(result_message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logging.info(f"[>>>] Risultato standard pubblicato su results_queue per {target} (task_id={task_id})")
        except Exception as e:
            logging.error(f"Errore pubblicando su results_queue: {e}")
    except Exception as e:
        logging.error(f"Errore nel task: {e}")
    finally:
        ch.basic_ack(delivery_tag=method.delivery_tag)

channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue=QUEUE, on_message_callback=callback)

try:
    channel.start_consuming()
except KeyboardInterrupt:
    logging.info('Interrotto da tastiera')
    channel.stop_consuming()
finally:
    connection.close() 