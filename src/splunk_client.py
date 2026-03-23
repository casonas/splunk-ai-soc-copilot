import csv
import io
import requests
from typing import List, Dict


class SplunkClient:
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = f"https://{host}:8089"
        self.auth = (username, password)
        self.verify_ssl = verify_ssl

    def run_search_csv(self, spl_query: str) -> List[Dict[str, str]]:
        """
        Run a Splunk search using jobs/export and return CSV rows as dicts.
        """
        url = f"{self.base_url}/services/search/jobs/export"
        payload = {
            "search": f"search {spl_query}",
            "output_mode": "csv",
            "exec_mode": "oneshot",
        }

        resp = requests.post(
            url,
            data=payload,
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=180,
        )
        resp.raise_for_status()

        csv_text = resp.text
        return list(csv.DictReader(io.StringIO(csv_text)))