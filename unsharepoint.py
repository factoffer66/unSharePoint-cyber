#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import urllib3
from libs.core.database import Database
from libs.core.logger import Logger
from libs.core.request import Request
from libs.core.target import Target
from libs.utils.banner import print_banner
from modules.check_cve import CheckCVE
from modules.check_bruteforce import BruteForce
from modules.check_sharepoint import Sharepoint
from modules.check_soap_api import CheckSoapApi
from modules.check_userenum import UserEnum
from modules.cmdline import gen_cli_args

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    print_banner()
    logger_inst = Logger()
    logger = logger_inst.get_logger()

    try:
        args = gen_cli_args()
        if args.verbose:
            logger_inst.enable_debug()

        # initialize HTTP layer (with NTLM if given)
        Request(args.domain, args.username, args.password)

        # set up our target
        tg = Target(args.url)

        # update DB if requested, then verify it’s in place
        db = Database()
        if args.update:
            db.update()
        db.verify_installation()

        # perform SharePoint checks
        sh = Sharepoint()
        resp = sh.check_availability()
        sh.check_iis_target(resp.headers)
        sh.check_share_point(resp.headers)

        # only run CVE lookup when we have a real version string
        sp = tg.sharepoint or {}
        ver = sp.get("version", "").lower()
        if ver and ver != "unknown":
            CheckCVE().get_cve()
        else:
            logger.info("Skipping CVE check: SharePoint version is unknown.")

        # optional SOAP/API scan
        if args.type in ('a', 'ad'):
            CheckSoapApi().check_soap_api(detailed=(args.type == 'ad'))

        # brute‑force or user enumeration
        if args.bruteforce:
            BruteForce(args.domain, args.username_file, args.password_file).bruteforce()
        if args.enum_users:
            UserEnum().user_enumeration()

        # final summary
        logger.info("Scan completed!")
        logger.info("Results:")

        # if we lack a release date, skip to_string() entirely
        date_val = sp.get("date")
        if date_val is None:
            # clean fallback without any exception
            version_str = sp.get("version", "Unknown")
            logger.info(f"SharePoint version: {version_str}, release date: N/A")
        else:
            # we have a date, so to_string() will format it properly
            logger.info(tg.to_string())

    except (KeyboardInterrupt, SystemExit):
        sys.exit(2)
    except Exception as e:
        logger.error(e)
        sys.exit(1)

if __name__ == "__main__":
    main()
