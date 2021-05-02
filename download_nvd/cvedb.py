"""
Retrieval access and caching of NIST CVE database
"""
import asyncio
import glob
import gzip
import hashlib
import json
import logging
import os
import re
import shutil

import aiohttp
from bs4 import BeautifulSoup
from rich.progress import track

from download_nvd.async_utils import FileIO, GzipFile, run_coroutine
from download_nvd.error_handler import (
    AttemptedToWriteOutsideCachedir,
    CVEDataForCurlVersionNotInCache,
    CVEDataForYearNotInCache,
    ErrorHandler,
    ErrorMode,
    SHAMismatch,
)
from download_nvd.log import LOGGER

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_DEFAULT = os.path.join(os.getcwd(),"NVD")


class CVEDB:
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    CACHEDIR = DISK_LOCATION_DEFAULT
    FEED = "https://nvd.nist.gov/vuln/data-feeds"
    LOGGER = LOGGER.getChild("CVEDB")
    NVDCVE_FILENAME_TEMPLATE = "nvdcve-1.1-{}.json.gz"
    CURL_CVE_FILENAME_TEMPLATE = "curlcve-{}.json"
    META_LINK = "https://nvd.nist.gov"
    META_REGEX = re.compile(r"\/feeds\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""

    def __init__(
        self,
        feed=None,
        cachedir=None,
        version_check=True,
        session=None,
        error_mode=ErrorMode.TruncTrace,
    ):
        self.feed = feed if feed is not None else self.FEED
        self.cachedir = cachedir if cachedir is not None else self.CACHEDIR
        self.error_mode = error_mode
        # Will be true if refresh was successful
        self.was_updated = False

        # version update
        self.version_check = version_check

        # set up the db if needed
        # self.dbpath = os.path.join(self.cachedir, DBNAME)
        self.connection = None
        self.session = session
        self.cve_count = -1
        
    async def getmeta(self, session, meta_url):
        async with session.get(meta_url) as response:
            return (
                meta_url.replace(".meta", ".json.gz"),
                dict(
                    [
                        line.split(":", maxsplit=1)
                        for line in (await response.text()).splitlines()
                        if ":" in line
                    ]
                ),
            )

    async def nist_scrape(self, session):
        async with session.get(self.feed) as response:
            page = await response.text()
            json_meta_links = self.META_REGEX.findall(page)
            return dict(
                await asyncio.gather(
                    *[
                        self.getmeta(session, f"{self.META_LINK}{meta_url}")
                        for meta_url in json_meta_links
                    ]
                )
            )

    async def cache_update(self, session, url, sha, chunk_size=16 * 1024):
        """
        Update the cache for a single year of NVD data.
        """
        filename = url.split("/")[-1]
        # Ensure we only write to files within the cachedir
        filepath = os.path.abspath(os.path.join(self.cachedir, filename))
        if not filepath.startswith(os.path.abspath(self.cachedir)):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise AttemptedToWriteOutsideCachedir(filepath)
        # Validate the contents of the cached file
        if os.path.isfile(filepath):
            # Validate the sha and write out
            sha = sha.upper()
            calculate = hashlib.sha256()
            async with GzipFile(filepath, "rb") as f:
                chunk = await f.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    chunk = await f.read(chunk_size)
            # Validate the sha and exit if it is correct, otherwise update
            gotsha = calculate.hexdigest().upper()
            if gotsha != sha:
                os.unlink(filepath)
                self.LOGGER.warning(
                    f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})"
                )
            else:
                self.LOGGER.debug(f"Correct SHA for {filename}")
                return
        self.LOGGER.debug(f"Updating CVE cache for {filename}")

        async with session.get(url) as response:
            gzip_data = await response.read()
        json_data = gzip.decompress(gzip_data)
        gotsha = hashlib.sha256(json_data).hexdigest().upper()
        async with FileIO(filepath, "wb") as filepath_handle:
            await filepath_handle.write(gzip_data)
        # Raise error if there was an issue with the sha
        if gotsha != sha:
            # Remove the file if there was an issue
            # exit(100)
            os.unlink(filepath)
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")

    @staticmethod
    async def get_curl_versions(session):
        regex = re.compile(r"vuln-(\d+.\d+.\d+)\.html")
        async with session.get(
            "https://curl.haxx.se/docs/vulnerabilities.html"
        ) as response:
            html = await response.text()
        matches = regex.finditer(html)
        return [match.group(1) for match in matches]

    async def download_curl_version(self, session, version):
        async with session.get(
            f"https://curl.haxx.se/docs/vuln-{version}.html"
        ) as response:
            html = await response.text()
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table")
        if not table:
            return
        headers = table.find_all("th")
        headers = list(map(lambda x: x.text.strip().lower(), headers))
        self.LOGGER.debug(headers)
        rows = table.find_all("tr")
        json_data = []
        for row in rows:
            cols = row.find_all("td")
            values = (ele.text.strip() for ele in cols)
            data = dict(zip(headers, values))
            if data:
                json_data.append(data)
        filepath = os.path.abspath(
            os.path.join(self.cachedir, f"curlcve-{version}.json")
        )
        async with FileIO(filepath, "w") as f:
            await f.write(json.dumps(json_data, indent=4))

    async def refresh(self):
        """ Refresh the cve database and check for new version. """
        # refresh the database
        if not os.path.isdir(self.cachedir):
            os.makedirs(self.cachedir)
        # check for the latest version
        if self.version_check:
            self.LOGGER.info("Checking if there is a newer version.")
            # check_latest_version()
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = aiohttp.ClientSession(connector=connector, trust_env=True)
        self.LOGGER.info("Downloading CVE data...")
        nvd_metadata, curl_metadata = await asyncio.gather(
            self.nist_scrape(self.session), self.get_curl_versions(self.session)
        )
        tasks = [
            self.cache_update(self.session, url, meta["sha256"])
            for url, meta in nvd_metadata.items()
            if meta is not None
        ]
        # We use gather to create a single task from a set of tasks
        # which download CVEs for each version of curl. Otherwise
        # the progress bar would show that we are closer to
        # completion than we think, because lots of curl CVEs (for
        # each version) have been downloaded
        tasks.append(
            asyncio.gather(
                *[
                    self.download_curl_version(self.session, version)
                    for version in curl_metadata
                ]
            )
        )
        total_tasks = len(tasks)

        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1:
            iter_tasks = track(
                asyncio.as_completed(tasks),
                description="Downloading CVEs...",
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(tasks)

        for task in iter_tasks:
            await task
        self.was_updated = True
        await self.session.close()
        self.session = None

    def refresh_cache_and_update_db(self):
        self.LOGGER.info("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        run_coroutine(self.refresh())

        # if the database isn't open, open it
        # self.init_database()
        # self.populate_db()


    def parse_node(self, node):
        affects_list = []
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                # self.LOGGER.debug(cpe_match["cpe23Uri"])
                cpe_split = cpe_match["cpe23Uri"].split(":")
                affects = {
                    "vendor": cpe_split[3],
                    "product": cpe_split[4],
                    "version": cpe_split[5],
                }

                # self.LOGGER.debug(
                #    "Vendor: {} Product: {} Version: {}".format(
                #        affects["vendor"], affects["product"], affects["version"]
                #    )
                # )
                # if we have a range (e.g. version is *) fill it out, and put blanks where needed
                range_fields = [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ]
                for field in range_fields:
                    if field in cpe_match:
                        affects[field] = cpe_match[field]
                    else:
                        affects[field] = self.RANGE_UNSET

                affects_list.append(affects)
        return affects_list

   

    def load_nvd_year(self, year):
        """
        Return the dict of CVE data for the given year.
        """
        filename = os.path.join(
            self.cachedir, self.NVDCVE_FILENAME_TEMPLATE.format(year)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with gzip.open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def nvd_years(self):
        """
        Return the years we have NVD data for.
        """
        return sorted(
            [
                int(filename.split(".")[-3].split("-")[-1])
                for filename in glob.glob(
                    os.path.join(self.cachedir, "nvdcve-1.1-*.json.gz")
                )
            ]
        )

    def load_curl_version(self, version):
        """
        Return the dict of CVE data for the given curl version.
        """
        filename = os.path.join(
            self.cachedir, self.CURL_CVE_FILENAME_TEMPLATE.format(version)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForCurlVersionNotInCache(version)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with open(filename, "rb") as fileobj:
            cves_for_version = json.load(fileobj)
            self.LOGGER.debug(
                f"Curl Version {version} has {len(cves_for_version)} CVEs in dataset"
            )
            return cves_for_version

    def curl_versions(self):
        """
        Return the versions we have Curl data for.
        """
        regex = re.compile(r"curlcve-(\d+.\d+.\d).json")
        return [
            regex.search(filename).group(1)
            for filename in glob.glob(os.path.join(self.cachedir, "curlcve-*.json"))
        ]

    def clear_cached_data(self):
        if os.path.exists(self.cachedir):
            self.LOGGER.warning(f"Deleting cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)
      
      

