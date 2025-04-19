# unsharepoint.py
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
    logger_instance = Logger()
    logger = logger_instance.get_logger()

    try:
        args = gen_cli_args()
        if args.verbose:
            logger_instance.enable_debug()

        Request(args.domain, args.username, args.password)
        tg = Target(args.url)

        db = Database()
        if args.update:
            db.update()
        db.verify_installation()

        sh = Sharepoint()
        response_obj = sh.check_availability()
        sh.check_iis_target(response_obj.headers)
        sh.check_share_point(response_obj.headers)

        # only run CVE check if we have a real numeric version
        sp = tg.sharepoint or {}
        ver = sp.get("version", "")
        if ver and ver.lower() != "unknown":
            check_cve = CheckCVE()
            check_cve.get_cve()
        else:
            logger.info("Skipping CVE check: SharePoint version is unknown.")

        if args.type != 'i':
            if args.type in ('a', 'ad'):
                soap_api = CheckSoapApi()
                soap_api.check_soap_api(detailed=(args.type == 'ad'))

        if args.bruteforce:
            BruteForce(args.domain, args.username_file, args.password_file).bruteforce()
        if args.enum_users:
            UserEnum().user_enumeration()

        logger.info("Scan completed!")
        logger.info("Results:")
        logger.info(tg.to_string())

    except (KeyboardInterrupt, SystemExit):
        sys.exit(2)
    except Exception as e:
        logger.error(e)
        sys.exit(1)

if __name__ == "__main__":
    main()
