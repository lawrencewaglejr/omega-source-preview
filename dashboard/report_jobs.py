"""Private asynchronous report generation from a consistent telemetry snapshot."""
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import shutil
import threading
import time
import zipfile

from devices import _directory
from telemetry_store import TelemetryStore
from correlation import analyze_events, build_ai_evidence, iter_html_report, iter_jsonl_events


class ReportJobs:
    def __init__(self, store, directory, ask_ai, devices, publish_analysis=None):
        self.store, self.directory = store, Path(directory) if directory else None
        self.ask_ai, self.devices, self.publish_analysis = ask_ai, devices, publish_analysis
        self.jobs = {}
        self.lock = threading.RLock()
        if self.directory:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            fd = _directory(self.directory, private=True); os.close(fd)

    def submit(self, owner, model):
        if not self.store or not self.directory:
            return 503, {"error":"Full reports require the connected persistent telemetry store on the live appliance."}
        if not model:
            return 503, {"error":"Connect a local AI model before generating an AI report."}
        with self.lock:
            for key in list(self.jobs):
                if self.jobs[key]["expires"] < time.monotonic():
                    self._remove_file(key)
                    del self.jobs[key]
            if any(job["state"] == "pending" for job in self.jobs.values()):
                return 429, {"error":"A full report is already being prepared. Please wait for it to finish."}
            if len(self.jobs) >= 3:
                oldest = min(self.jobs, key=lambda key:self.jobs[key]["expires"])
                self._remove_file(oldest); del self.jobs[oldest]
            key = secrets.token_hex(16)
            self.jobs[key] = {"owner":owner,"expires":time.monotonic()+3600,"state":"pending","progress":"Freezing a consistent copy of the collected evidence…"}
        threading.Thread(target=self._run,args=(key,model),daemon=True,name="omega-full-report").start()
        return 202, {"id":key,"state":"pending"}

    def _remove_file(self, key):
        if self.directory:
            (self.directory / (key+".zip")).unlink(missing_ok=True)

    def _update(self, key, **values):
        with self.lock:
            self.jobs[key].update(values)

    def busy(self):
        with self.lock:
            return any(job["state"] == "pending" for job in self.jobs.values())

    def _run(self, key, model):
        frozen = None
        archive = self.directory / (key+".zip")
        try:
            if shutil.disk_usage(self.directory).free < 2*1024**3:
                raise OSError("Insufficient report storage")
            frozen = self.store.freeze()
            snapshot = frozen.snapshot()
            devices = self.devices()
            self._update(key, progress=f'Correlating {snapshot["events"]:,} retained events across available sources…')
            def evidence_records():
                for index, event in enumerate(frozen.iter_events()):
                    if index % 100000 == 0:
                        self._update(key,progress=f'Correlating collected evidence: {index:,} of {snapshot["events"]:,} events checked…')
                        if shutil.disk_usage(self.directory).free < 2*1024**3:
                            raise OSError("Report storage limit reached")
                    yield event
            analysis = analyze_events(evidence_records(), coverage=snapshot["coverage"], sources=snapshot["sources"], known_ips=[address for device in devices["devices"] for address in device.get("addresses",[device["ip"]])])
            if self.publish_analysis:
                self.publish_analysis(analysis)
            self._update(key, progress="The local AI is analyzing the combined evidence and correlation candidates…")
            evidence = build_ai_evidence(analysis)
            deadline = time.monotonic()+240
            while True:
                code, response = self.ask_ai("Begin with one exact candidate ID from the evidence. In at most 70 words, explain what that candidate shows and suggest one next check. Do not repeat counts. Do not infer attacks from shared IP/time or treat Wazuh copies of Suricata as independent evidence.", evidence)
                if code != 429 or time.monotonic() >= deadline:
                    break
                time.sleep(3)
            ai_ok = code == 200
            ai = {"model":model, "answer":response.get("answer") if ai_ok else "AI analysis unavailable: "+response.get("error","The model did not return an answer.")}
            generated = dt.datetime.now(dt.timezone.utc).isoformat()
            self._update(key, progress="Packaging the readable report and complete structured event export…")
            fd = os.open(archive, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,"wb") as output, zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as bundle:
                bundle.writestr("OMEGA-report.html", "".join(iter_html_report((),analysis,ai_analysis=ai,generated=generated,devices=devices,include_events=False)))
                bundle.writestr("coverage-and-correlations.json", json.dumps(analysis,indent=2))
                bundle.writestr("devices.json", json.dumps(devices,indent=2))
                bundle.writestr("README.txt", "Open OMEGA-report.html for the combined assessment. events.jsonl contains every retained normalized event in this consistent snapshot. source-events.jsonl preserves original collected sensor records. Coverage and exclusions are recorded in the report. AI evaluates aggregates from retained events and selected evidence, not every raw event individually.\n")
                with bundle.open("events.jsonl","w",force_zip64=True) as records:
                    for index, line in enumerate(iter_jsonl_events(frozen.iter_events())):
                        records.write(line.encode())
                        if index % 10000 == 0 and shutil.disk_usage(self.directory).free < 2*1024**3:
                            raise OSError("Report storage limit reached")
                with bundle.open("source-events.jsonl","w",force_zip64=True) as records:
                    for index, event in enumerate(frozen.iter_original_events()):
                        records.write((json.dumps(event,separators=(",",":"))+"\n").encode())
                        if index % 10000 == 0 and shutil.disk_usage(self.directory).free < 2*1024**3:
                            raise OSError("Report storage limit reached")
            self._update(key,state="complete",generated=generated,ai_available=ai_ok,progress="Report ready." if ai_ok else "Report ready; the AI analysis could not be completed.",download_url=f"/api/reports/{key}/download")
        except Exception as error:
            archive.unlink(missing_ok=True)
            self._update(key,state="failed",error="The full report could not be generated. Check telemetry storage, source availability, and free disk space.",diagnostic=type(error).__name__)
        finally:
            if frozen:
                frozen.close()

    def get(self, key, owner, download=False):
        with self.lock:
            job = self.jobs.get(key)
            if not job or job["owner"] != owner or job["expires"] < time.monotonic():
                return 404, {"error":"This report is no longer available. Generate it again."}
            if download:
                if job["state"] != "complete":
                    return 409, {"error":"The report is not ready yet."}
                return 200, self.directory / (key+".zip")
            return 200, {"id":key, **{k:v for k,v in job.items() if k not in {"owner","expires"}}}
