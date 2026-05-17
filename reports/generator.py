import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.findings = {}
        self.start_time = datetime.now().isoformat()

    def add_findings(self, module_name, findings):
        if not findings:
            return
        
        # Convert dataclasses to dicts if they aren't already
        serializable_findings = []
        for f in findings:
            if hasattr(f, "__dict__"):
                serializable_findings.append(f.__dict__)
            else:
                serializable_findings.append(f)
                
        self.findings[module_name] = serializable_findings

    def generate(self, formats, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        paths = {}
        
        report_data = {
            "target": self.target,
            "scan_time": self.start_time,
            "findings": self.findings
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"report_{timestamp}"

        if "terminal" in formats:
            for mod, finds in self.findings.items():
                print(f"\n[{mod}] Findings: {len(finds)}")
                for f in finds:
                    print(f" - {f.get('severity', 'INFO')}: {f.get('url', 'N/A')}")
            
        if "json" in formats:
            path = os.path.join(output_dir, f"{base_name}.json")
            with open(path, "w") as f:
                json.dump(report_data, f, indent=4)
            paths["json"] = path
            
        if "html" in formats:
            path = os.path.join(output_dir, f"{base_name}.html")
            with open(path, "w") as f:
                f.write(f"<html><body><h1>AutoVulnX Report for {self.target}</h1>")
                for mod, finds in self.findings.items():
                    f.write(f"<h2>{mod}</h2><ul>")
                    for f_item in finds:
                        f.write(f"<li>{f_item.get('severity')}: {f_item.get('url')} - {f_item.get('parameter')}</li>")
                    f.write("</ul>")
                f.write("</body></html>")
            paths["html"] = path
            
        return paths
