# modules/check_sharepoint.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Copyright (C) 2020 CYS4 Srl
See the file 'LICENSE' for copying permission
"""

import os
from datetime import datetime

from libs.core.logger import Logger
from libs.core.request import Request
from libs.core.target import Target
import libs.core.constants as constants

class Sharepoint:
    _instance = None
    logger = None
    target = None
    request = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Sharepoint, cls).__new__(cls)
            cls._instance.init_sharepoint()
        return cls._instance

    def init_sharepoint(self):
        self.logger = Logger().get_logger()
        self.target = Target()
        self.request = Request()

    def check_availability(self):
        self.logger.debug("check_availability")
        try:
            r = self.request.request_get(self.target.url)
            if r.status_code != 200:
                self.logger.warning(
                    "Please take attention, the target answered with %i code." % r.status_code
                )
        except Exception:
            raise ValueError("Unhandled error on check_availability().")
        return r

    def check_iis_target(self, headers):
        self.logger.debug("check_iis_target")
        detected_version_iis = detect_server_by_headers(headers)
        if detected_version_iis:
            self.target.server = detected_version_iis
            self.logger.debug(
                "Server version Detected (headers parse): {}".format(detected_version_iis)
            )

        detected_tec = detect_tec_by_headers(headers)
        if detected_tec:
            self.target.technology = detected_tec
            self.logger.debug(
                "Technology detected (headers parse): {}".format(detected_tec)
            )

    def check_share_point(self, headers):
        self.logger.debug("check_share_point")

        # try headers first
        detected_version_share_point = self.detect_sharepoint_by_headers(headers)
        if detected_version_share_point:
            self.logger.debug(
                "SharePoint version Detected (headers parse): {}".format(
                    detected_version_share_point
                )
            )
        else:
            # fallback to service file
            detected_version_share_point = self.detect_sharepoint_by_servicefile()
            if detected_version_share_point:
                self.logger.debug(
                    "SharePoint version Detected (service.cnf parse): {}".format(
                        detected_version_share_point
                    )
                )

        if detected_version_share_point:
            self.get_version(detected_version_share_point)
        else:
            self.logger.error(
                "Unable to detect SharePoint version; get_version will not be executed."
            )
            # ensure .sharepoint is always a dict so to_string() won't crash
            self.target.sharepoint = {
                "version": "Unknown",
                "date": None
            }

    def detect_sharepoint_by_headers(self, headers):
        self.logger.debug("detect_sharepoint_by_headers")
        useful_headers = [
            header for header in headers if "sharepoint" in header.lower()
        ]
        if "MicrosoftSharePointTeamServices" in headers.keys():
            version = headers["MicrosoftSharePointTeamServices"] \
                        .split(";")[0] \
                        .split(":")[0]
            return version
        elif useful_headers:
            self.logger.warning(
                "Header %s was found, it may not bring the exact version." %
                headers[useful_headers[0]].replace("\r\n", "")
            )
        return None

    def detect_sharepoint_by_servicefile(self):
        self.logger.debug("detect_sharepoint_by_servicefile")
        version = None
        for service_url in constants.SHAREPOINT_SERVICE_URLS:
            try:
                r = self.request.request_get(self.target.url + service_url)
                if r.status_code == 200:
                    if "vti_extenderversion" in r.text:
                        version = r.text.split("vti_extenderversion:SR|")[1].strip()
                        break
                    if "vti_buildversion" in r.text:
                        version = r.text.split("vti_extenderversion:SR|")[1].strip()
                        break
            except Exception:
                raise ValueError("Unhandled error detect_sharepoint_by_servicefile().")
        return version

    def get_version(self, patch_number):
        # patch_number guaranteed non-None here
        tokens = patch_number.split(".")
        major = int(tokens[0])
        minor = int(tokens[1])
        build = int(tokens[3])
        lookup_version = f"{major}.{minor}.{build}"

        db_version = {"version": "", "date": ""}
        csv_path = os.path.join(constants.DATABASE_FOLDER, "versions.csv")
        with open(csv_path, "r") as file_versions:
            for line in file_versions:
                parts = line.strip().split(",")
                version_parts = parts[0].split(".")
                date_str = parts[2]
                if len(version_parts) < 4:
                    continue

                v_major, v_minor, v_build = map(int, version_parts[:3])
                v_date = (
                    datetime.strptime(date_str, "%Y %B %d")
                    if date_str != "N/A"
                    else None
                )
                formatted = f"{v_major}.{v_minor}.{v_build}"

                if formatted == lookup_version:
                    db_version["version"] = formatted
                    db_version["date"] = v_date
                    self.logger.info("Version details found.")
                    break

                if (major > v_major) or (major == v_major and build > v_build):
                    db_version["version"] = formatted
                    db_version["date"] = v_date
                    self.logger.info("Version could not be found, performing best guess.")
                    break

        self.target.sharepoint = db_version


def detect_server_by_headers(headers):
    return headers.get("Server", None)


def detect_tec_by_headers(headers):
    return headers.get("X-Powered-By", None)
