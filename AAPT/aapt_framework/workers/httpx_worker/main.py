import os
import json
import pika
import asyncio
import aiofiles
import subprocess
import uuid
from datetime import datetime
from flask import Flask, jsonify
import threading
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from recon_db import insert_httpx_probe

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
QUEUE = 'httpx_tasks'
RESULTS_QUEUE = 'results_queue'

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials, heartbeat=600)

app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8084, debug=False, use_reloader=False)

async def run_httpx(target, task_id):
    output_file = f"httpx_{task_id}.json"
    cmd = [
        "httpx", "-u", target, "-json", "-o", output_file, "-title", "-tech-detect", "-status-code", "-server", "-cname", "-ip"
    ]
    proc = await asyncio.create_subprocess_exec(*cmd)
    await proc.communicate()
    # Leggi risultati
    results = []
    try:
        async with aiofiles.open(output_file, 'r') as f:
            async for line in f:
                try:
                    data = json.loads(line)
                    results.append(data)
                    insert_httpx_probe(
                        target,
                        data.get('status_code'),
                        data.get('title'),
                        data.get('tech'),
                        data.get('server'),
                        data.get('cname'),
                        data.get('ip'),
                        data.get('title') or '',
                        data.get('port', 80),
                        data.get('cve', None),
                        int(data.get('cname_takeover', False))
                    )
                except Exception:
                    continue
    except Exception:
        pass
    # Cleanup
    try:
        os.remove(output_file)
    except Exception:
        pass
    return results

def publish_result(channel, target, httpx_results, task_id):
    # Prendi il primo risultato valido (httpx lavora per target, ma può restituire più entry)
    data = httpx_results[0] if httpx_results else {}
    result = {
        "task_id": task_id,
        "worker_type": "httpx_worker",
        "target": target,
        "status": "success" if data else "failure",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": f"HTTP probe su {target}: {data.get('status_code', 'no response')} {data.get('title', '')}",
        "data": {
            "status_code": data.get('status_code'),
            "title": data.get('title'),
            "tech": data.get('tech'),
            "server": data.get('server'),
            "cname": data.get('cname'),
            "ip": data.get('ip'),
            "url": data.get('url'),
            "banner": data.get('title') or '',
            "port": data.get('port', 80),
            "cve": data.get('cve', None),
            "cname_takeover": data.get('cname_takeover', False)
        } if data else {}
    }
    channel.queue_declare(queue=RESULTS_QUEUE, durable=True)
    channel.basic_publish(
        exchange='',
        routing_key=RESULTS_QUEUE,
        body=json.dumps(result),
        properties=pika.BasicProperties(delivery_mode=2)
    )

def process_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        if not target:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        httpx_results = loop.run_until_complete(run_httpx(target, task_id))
        publish_result(channel, target, httpx_results, task_id)
    except Exception as e:
        print(f"Errore nel process_task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)

def main():
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    while True:
        try:
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=QUEUE, on_message_callback=lambda ch, m, p, b: process_task(ch, m, p, b))
            health_status["status"] = "ok"
            print("[*] httpx_worker in ascolto su coda httpx_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            print(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main() 