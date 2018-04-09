#!/usr/bin/env python
#  -*- coding: UTF-8 -*-

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os
import sys
import threading
import time


sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../common"))
from comp_status_cli_interface import init_comp_status_cli, send_comp_status, final_comp_status_cli
import settings


try:
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT, REPORT_ROOT
    from lib.cuckoo.common.exceptions import CuckooCriticalError
    from lib.cuckoo.common.exceptions import CuckooDependencyError
    from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
    from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
    from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
    from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING
    from lib.cuckoo.core.startup import check_working_directory, check_configs, check_signatures, cuckoo_clean
    from lib.cuckoo.core.startup import check_version, create_structure
    from lib.cuckoo.core.startup import init_logging, init_modules, init_console_logging
    from lib.cuckoo.core.startup import init_tasks, init_yara
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.resultserver import ResultServer
    from lib.cuckoo.core.file_type import pd_fmt_file

    import bson

    bson  # Pretend like it's actually being used (for static checkers.)
except (CuckooDependencyError, ImportError) as e:
    sys.exit("ERROR: Missing dependency: {0}".format(e))

log = logging.getLogger()


class CMPHeartBeatThread(threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name

    def run(self):
        # if not init_comp_status_cli():
        #     log.critical('init comp status client failed')
        #     sys.exit(-1)

        while True:
            self.proc()
            time.sleep(60)

        final_comp_status_cli()

    def proc(self):
        try:
            send_comp_status(settings.comp_name_sandbox)
        except Exception as e:
            log.debug("{0}".format(e))
            return


def cuckoo_init(quiet=False, debug=False, artwork=False, test=False):
    cur_path = os.getcwd()
    os.chdir(CUCKOO_ROOT)

    logo()
    check_working_directory()
    check_configs()
    check_signatures()
    check_version()
    create_structure()

    if artwork:
        import time

        try:
            while True:
                time.sleep(1)
                logo()
        except KeyboardInterrupt:
            return

    init_logging()

    if quiet:
        log.setLevel(logging.WARN)
    elif debug:
        log.setLevel(logging.DEBUG)

    init_modules()
    init_tasks()
    init_yara()

    # This is just a temporary hack, we need an actual test suite to integrate
    # with Travis-CI.
    if test:
        return

    ResultServer()

    os.chdir(cur_path)


def cuckoo_main(max_analysis_count=0):
    cur_path = os.getcwd()
    os.chdir(CUCKOO_ROOT)

    try:
        sched = Scheduler(max_analysis_count)
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

    os.chdir(cur_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version",
                        version="You are running Cuckoo Sandbox {0}".format(CUCKOO_VERSION))
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-t", "--test", help="Test startup", action="store_true", required=False)
    parser.add_argument("-m", "--max-analysis-count", help="Maximum number of analyses", type=int, required=False)
    parser.add_argument("--clean", help="Remove all tasks and samples and their associated data", action='store_true',
                        required=False)

    parser.add_argument("--notifyclose", help="send close signal to watchdog server", action='store_true')



    args = parser.parse_args()

    if args.notifyclose:
        final_comp_status_cli(settings.comp_name_sandbox)
        sys.exit(0)

    if args.clean:
        cuckoo_clean()
        sys.exit(0)

    try:
        cmp_hb_thrd = CMPHeartBeatThread(1, "comp heartbeat thread")
        cmp_hb_thrd.start()

        cuckoo_init(quiet=args.quiet, debug=args.debug, artwork=args.artwork, test=args.test)
        if not args.artwork and not args.test:
            cuckoo_main(max_analysis_count=args.max_analysis_count)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers):
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))

        sys.exit(1)
