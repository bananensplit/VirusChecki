import logging
import time
from concurrent.futures import ThreadPoolExecutor

import requests


class VirusTotalHandler:
    def __init__(self, logger: logging.Logger, API_KEY: str = None) -> None:
        if API_KEY is None:
            raise ValueError("API_TOKEN is required")
        self.API_TOKEN = API_KEY
        self.logger = logger
        self.threadpool = ThreadPoolExecutor(max_workers=1)

    async def scan_url(self, url: str) -> dict:
        future = self.threadpool.submit(VirusTotalHandler.virus_total_job, url, self.logger, self.API_TOKEN)
        return future.result()
    
    @staticmethod
    def virus_total_job(url, logger: logging.Logger, API_KEY: str = None) -> None:
        # scan the URL
        scan_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={
                "x-apikey": API_KEY,
                "accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"url": url},
        )
        logger.debug(scan_response.json())
        logger.info("Waiting for 25 seconds...")
        time.sleep(25)

        analysis_fetch_link = scan_response.json()["data"]["links"]["self"]
        report_response = requests.get(analysis_fetch_link, headers={"x-apikey": API_KEY})
        logger.debug(report_response.json())
        logger.info("Waiting for 25 seconds...")
        time.sleep(25)
        return report_response.json()
