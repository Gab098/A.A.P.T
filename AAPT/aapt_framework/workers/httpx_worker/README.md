# Httpx Worker (A.A.P.T.)

## Panoramica
Worker per probe HTTP/HTTPS, tech detection, banner, CNAME, status code. Scrive risultati su RabbitMQ e su SQLite (`recon.db`).

## Pipeline
- Probe automatico su ogni nuovo subdominio trovato.
- Output: probe pubblicati su results_queue e salvati in SQLite.
- Asset attivi/interessanti importati in Neo4j solo se confermati.

## Sicurezza e Hardening
- Container non root
- Input target validato
- Aggiorna regolarmente httpx
- Limita rate di probe su target

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 