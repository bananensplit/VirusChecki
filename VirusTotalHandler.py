import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor

import requests


class VirusTotalHandler:
    def __init__(self, logger: logging.Logger, API_KEY: str = None) -> None:
        if API_KEY is None:
            raise ValueError("API_TOKEN is required")
        self.API_TOKEN = API_KEY
        self.logger = logger
        self.threadpool = ThreadPoolExecutor(max_workers=1)

    async def scan_url(self, url: str) -> dict:
        result_future = Future()
        self.threadpool.submit(VirusTotalHandler.virus_total_job, url, result_future, self.logger, self.API_TOKEN)
        self.logger.info(f"Queued attachment - URL: {url}")
        return result_future.result()

    @staticmethod
    def virus_total_job(url: str, future: Future, logger: logging.Logger, api_key: str = None) -> None:
        # sending the scan request
        logger.info(f"Scanning attachment - URL: {url}")
        scan_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={
                "x-apikey": api_key,
                "accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"url": url},
            timeout=20,
        )

        logger.debug(f"Scan response - URL: {url}: \n{scan_response.json()}")
        logger.info("Waiting for 25 seconds... (VirusTotal has a ratelimit)")
        time.sleep(25)

        # fetching the report from the scan
        logger.info(f"Fetching report for attachment - URL: {url}")
        analysis_fetch_link = scan_response.json()["data"]["links"]["self"]
        report_response = requests.get(analysis_fetch_link, headers={"x-apikey": api_key}, timeout=20)
        future.set_result(report_response.json())

        logger.debug(f"Report response - URL: {url}: \n{report_response.json()}")
        logger.info("Waiting for 25 seconds... (VirusTotal has a ratelimit)")
        time.sleep(25)
        return True
