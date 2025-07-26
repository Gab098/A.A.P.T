import logging
import json
import time
import os
import re
from typing import Dict, Any
from llama_cpp import Llama

class LLMPlanner:
    def __init__(self, model_path: str = "./models/Microsoft/phi-3mini-4k-instruct-q43mini-4k-instruct-q4.gguf"):
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path
        self.llm = None
        self._load_model()
        self.history_file = "llm_history.json"
        self.history = self._load_history()

    def _load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Errore nel caricamento della cronologia LLM: {e}")
        return []

    def _save_history(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"Errore nel salvataggio della cronologia LLM: {e}")

    def _load_model(self):
        if not os.path.exists(self.model_path):
            self.logger.error(f"Modello non trovato: {self.model_path}")
            raise FileNotFoundError(f"Modello non trovato: {self.model_path}")
        self.llm = Llama(
            model_path=self.model_path,
            n_ctx=4096,
            n_threads=4,
            n_gpu_layers=0,
            verbose=False
        )
        self.logger.info(f"Modello Phi-3 caricato da: {self.model_path}")

    def _create_system_prompt(self) -> str:
        return (
            "Sei un assistente di ricognizione passiva e pentesting intelligente. Il tuo compito è analizzare lo stato del sistema e pianificare le prossime azioni per identificare opportunità di attacco, vulnerabilità e asset interessanti.\n"
            "Rispondi SOLO con un blocco JSON valido racchiuso tra ```json e ``` (senza testo prima o dopo)."
            "Esempio:\n"
            "```json\n{\n  \"action\": \"subfinder\", ...}\n```"
            "CONTESTO:\n"
            "- Stai operando su un sistema di ricognizione continua chiamato A.A.P.T.\n"
            "- Hai accesso a worker per subfinder (sottodomini), httpx (probe/tech), naabu (port scan leggero), nuclei (vulnerabilità mirate), nmap/msf (solo su trigger manuale/alta confidenza), privesc.\n"
            "- I risultati vengono salvati in Neo4j (asset attivi/interessanti) e SQLite (ricognizione grezza).\n"
            "- Devi massimizzare la copertura, la scoperta di asset e vulnerabilità ad alto impatto, minimizzando il carico sul sistema.\n"
            "TOOLBOX:\n"
            "1. subfinder: Enumera sottodomini di un dominio. Parametri: domain\n"
            "2. httpx_probe: Esegue probe HTTP/HTTPS, rileva status, title, tech, banner, CNAME, IP. Parametri: target (dominio/sottodominio)\n"
            "3. naabu_scan: Scansione porte veloce su target. Parametri: target\n"
            "4. nuclei_scan: Scansione vulnerabilità mirata. Parametri: target, templates (CVE, tech, ecc.)\n"
            "5. nmap_scan: Scansione approfondita (solo su richiesta/manuale).\n"
            "6. msf_exploit: Exploit solo su vulnerabilità confermate.\n"
            "7. privesc: Privilege escalation su shell ottenute.\n"
            "8. wait: Attendi nuovi asset/eventi.\n"
            "SEQUENZA RACCOMANDATA:\n"
            "- 1. subfinder su domini configurati\n"
            "- 2. httpx_probe su ogni nuovo sottodominio\n"
            "- 3. naabu_scan su asset attivi\n"
            "- 4. nuclei_scan mirato SOLO se tech/banner/cve suggeriscono vulnerabilità ad alto impatto\n"
            "- 5. nmap/msf solo su trigger manuale o alta confidenza\n"
            "- 6. privesc solo su shell ottenute\n"
            "REGOLE:\n"
            "- Non sovraccaricare il sistema: limita task pesanti, prediligi ricognizione passiva e probe leggeri.\n"
            "- Lancia nuclei_scan solo se hai una motivazione chiara (es: tech rilevata con CVE nota, banner sospetto, CNAME takeover, ecc.).\n"
            "- Se trovi solo anomalie, aggiungi il target alla lista 'Obiettivi Interessanti' (priority: medium/low) e notifica l'utente.\n"
            "- Non lanciare nmap/msf senza una vulnerabilità confermata. Notifica e attendi conferma.\n"
            "- Massimizza la scoperta di asset e vulnerabilità critiche, minimizza falsi positivi e carico.\n"
        )

    def _create_planning_prompt(self, system_state: Dict[str, Any]) -> str:
        prompt = self._create_system_prompt()
        prompt += f"\nSTATO ATTUALE DEL SISTEMA:\n{json.dumps(system_state, indent=2, ensure_ascii=False)}\n"
        prompt += f"\nTASK PENDENTI:\n{json.dumps(system_state.get('pending_tasks', []), indent=2, ensure_ascii=False)}\n"
        prompt += ("\nANALIZZA lo stato e DECIDI la prossima azione. Rispondi con un JSON nel seguente formato:\n"
                   "```json\n{\n  \"action\": subfinder|httpx_probe|naabu_scan|nuclei_scan|wait|analyze,\n  \"target\": \"DOMINIO_O_IP\",\n  \"reasoning\": \"Spiegazione della decisione\",\n  \"priority\": \"high|medium|low\",\n  \"parameters\": { ... }\n}\n```\n"
                   "Se scegli 'wait', non includere target o parameters.")
        return prompt

    def plan_next_action(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        try:
            prompt = self._create_planning_prompt(system_state)
            self.history.append({"role": "user", "content": prompt})
            response = self.llm(
                messages=self.history,
                max_tokens=512,
                temperature=0.1,
                stop=["```", "---\n\n"]
            )
            response_text = response['choices'][0]['text'].strip()
            self.logger.info(f"Risposta LLM: {response_text}")
            match = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL)
            if match:
                json_str = match.group(1)
                action_plan = json.loads(json_str)
                self.logger.info(f"Piano generato: {action_plan}")
                self.history.append({"role": "assistant", "content": response_text})
                self._save_history()
                return action_plan
            else:
                self.logger.error("Nessun blocco JSON trovato nella risposta LLM")
                self._save_history()
                return self._fallback_action(system_state)
        except Exception as e:
            self.logger.error(f"Errore nella pianificazione: {e}")
            self._save_history()
            return self._fallback_action(system_state)

    def _fallback_action(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        pending_tasks = system_state.get('pending_tasks', [])
        if pending_tasks:
            # Se ci sono task pendenti, esegui nmap sul primo
            target = pending_tasks[0]
            return {"action": "nmap_scan", "target": target.get('ip') or target.get('domain'), "reasoning": "Fallback: scan nmap su target pendente", "priority": "medium", "parameters": {"ports": 1-1000}}
        else:
            # Se non ci sono task, aspetta
            return {"action": "wait", "reasoning": "Fallback: nessun target disponibile", "priority": "low"}

    def analyze_results(self, target_details: Dict[str, Any]) -> Dict[str, Any]:
        try:
            prompt = self._create_system_prompt()
            prompt += f"\nANALISI TARGET:\n{json.dumps(target_details, indent=2, ensure_ascii=False)}\n"
            prompt += ("\nAnalizza i risultati esistenti e suggerisci prossimi scan. Rispondi con JSON:\n"
                       "```json\n{\n  \"recommendations\": [\n    {\n      \"action\": \"nuclei_scan|nmap_scan\",\n      \"target\": \"IP_OR_DOMAIN\",\n      \"reasoning\": \"Perché questo scan è necessario\",\n      \"priority\": \"high|medium|low\",\n      \"parameters\": {\n        \"ports\": \"specific_ports\",\n        \"templates\": \"specific_templates\"\n      }\n    }\n  ],\n  \"summary\": \"Riassunto dell'analisi\"\n}\n```\n")

            response = self.llm(
                prompt,
                max_tokens=1024,
                temperature=0.2,
                stop=["```", "---\n\n"]
            )

            response_text = response['choices'][0]['text'].strip()
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1

            if json_start != -1 and json_end > 0:
                json_str = response_text[json_start:json_end]
                analysis = json.loads(json_str)
                self.logger.info(f"Analisi completata: {analysis}")
                return analysis
            else:
                return {"recommendations": [], "summary": "Errore nell'analisi"}
        except Exception as e:
            self.logger.error(f"Errore nell'analisi: {e}")
            return {"recommendations": [], "summary": f"Errore: {str(e)}"}

    def close(self):
        if self.llm:
            del self.llm
            self.llm = None 