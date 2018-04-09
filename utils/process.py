#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import os
from os import path
import sys
import time
import logging
import logging.handlers
import argparse
import signal
import multiprocessing
import json
import shutil
from datetime import datetime

log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import REPORT_ROOT, LOG_ROOT
from lib.cuckoo.core.database import Database, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.plugins import GetFeeds, RunProcessing, RunSignatures
from lib.cuckoo.core.plugins import RunReporting
from lib.cuckoo.core.startup import init_modules, ConsoleHandler
from lib.cuckoo.core.generate_result import generate_result
from lib.cuckoo.common.objects import File
from lib.cuckoo.core.file_type import pd_fmt_file


def process(task_id, target=None, copy_path=None, report=False, auto=False):
    assert isinstance(task_id, int)
    # This is the results container. It's what will be used by all the
    # reporting modules to make it consumable by humans and machines.
    # It will contain all the results generated by every processing
    # module available. Its structure can be observed through the JSON
    # dump in the analysis' reports folder. (If jsondump is enabled.)
    results = {}
    db = Database()
    if os.path.exists(os.path.join(REPORT_ROOT, "storage", "analyses", str(task_id), "logs")):
        GetFeeds(results=results).run()
        RunProcessing(task_id=task_id, results=results).run()
        RunSignatures(task_id=task_id, results=results).run()
    if report:
        try:
            task = db.view_task(task_id)
            results = generate_result(task, results)
            RunReporting(task_id=task_id, results=results).run()
            db.set_status(task_id, TASK_REPORTED)
        except Exception as e:
            log.error("Task #%d: reports generation failed: %s", task_id, e)
            db.set_status(task_id, TASK_FAILED_REPORTING)
        finally:
            del results

        if auto:
            if cfg.cuckoo.delete_original and os.path.exists(target):
                os.unlink(target)

            if cfg.cuckoo.delete_bin_copy and os.path.exists(copy_path):
                os.unlink(copy_path)

        if task_id < 0 and task.mode < 2:
            json_reports = []
            targets = []
            started = []
            completed = []
            sub_tasks = db.list_subtasks(task_id)
            for sub_task in sub_tasks:
                if sub_task.status not in [TASK_REPORTED, TASK_FAILED_REPORTING,
                                           TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING]:
                    return

                json_path = path.join(REPORT_ROOT, "storage", "analyses", str(sub_task.id), "reports", "report.json")
                if path.exists(json_path):
                    json_report = json.load(open(json_path))
                    json_reports.append(json_report)
                    targets.append(sub_task.target)
                started.append(sub_task.started_on)
                completed.append(sub_task.completed_on)

            scores = [report["scores"] for report in json_reports]
            # get the highest scores report
            base_report = json_reports[scores.index(max(scores))]
            base_assessment_result = {
                "scores": base_report["scores"], "severity": base_report["severity"],
                "summary": base_report["summary"], "details": base_report["details"],
                "description": base_report["description"]
            }

            # get parent_task details
            parent_task = db.view_parent_task(task_id)
            log.debug("#%d: sub tasks reported, start to generate the final report." % parent_task.id)

            # get parent_task start and complete time
            started = min(started)
            completed = max(completed)
            db.set_time(parent_task.id, "started_on", started)
            db.set_time(parent_task.id, "completed_on", completed)
            duration = (completed - started).seconds

            targetdetail = {}
            if os.path.exists(parent_task.target):
                filedetail = File(parent_task.target).get_all()
                fmt_file = pd_fmt_file(parent_task.target.encode("utf-8"))
                targetdetail = {
                    "target": filedetail["name"], "size": filedetail["size"], "extnomatch": 1 - fmt_file[1],
                    "type": fmt_file[2], "md5": filedetail["md5"], "sha1": filedetail["sha1"]
                }
            report_result = {
                "category": parent_task.category, "targetdetail": targetdetail,
                "reporttime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "duration": duration,
                "started": started.strftime("%Y-%m-%d %H:%M:%S"), "ended": completed.strftime("%Y-%m-%d %H:%M:%S"),
            }

            report_result.update(base_assessment_result)
            report_result["file_reports"] = json_reports

            try:
                reports_path = os.path.join(REPORT_ROOT, "storage", "analyses", str(parent_task.id), "reports")
                if not os.path.exists(reports_path):
                    os.makedirs(reports_path)
                RunReporting(task_id=parent_task.id, results=report_result).run()
                db.set_status(parent_task.id, TASK_REPORTED)
                log.info("Task #%d: reports generation completed (path=%s)", parent_task.id, reports_path)
            except Exception as e:
                log.error("#%s generate report failed, msg:%s" % (parent_task.id, e))
                db.set_status(parent_task.id, TASK_FAILED_REPORTING)
            finally:
                del report_result

            # remove uncompressed dir and delete all sub tasks and their storage if they exist
            _tail = "_z1p2d1r"
            uncompressed_dir = parent_task.target + _tail
            if path.exists(uncompressed_dir):
                shutil.rmtree(uncompressed_dir, ignore_errors=True)

            try:
                for sub_task in sub_tasks:
                    db.delete_task(sub_task.id)
                    db.delete_result(sub_task.id)
                    db.delete_sub_task(sub_task.id)
                    task_path = path.join(REPORT_ROOT, "storage", "analyses", str(sub_task.id))
                    if path.exists(task_path):
                        shutil.rmtree(task_path, True)
                log.info("Delete submitted tasks successfully")
            except Exception as e:
                log.info("Delete submitted tasks failed, msg: %s" % e)

        if task_id < 0 and task.mode == 2:
            json_reports = []
            targets = []
            report_path = []
            sub_tasks = db.list_subtasks(task_id)
            for sub_task in sub_tasks:
                if sub_task.status not in [TASK_REPORTED, TASK_FAILED_REPORTING,
                                           TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING]:
                    return

                json_path = path.join(REPORT_ROOT, "storage", "analyses", str(sub_task.id), "reports", "report.json")
                if path.exists(json_path):
                    json_report = json.load(open(json_path))
                    json_reports.append(json_report)
                    targets.append(sub_task.target)
                    report_path.append(path.join(REPORT_ROOT, "storage", "analyses", str(sub_task.id)))
            max_malscore_index = max(enumerate(json_reports), key=lambda x: x[1]["scores"])[0]
            parent_task = db.view_parent_task(task_id)
            db.set_time(parent_task.id, "started_on", json_reports[max_malscore_index]["started"])
            db.set_time(parent_task.id, "completed_on", json_reports[max_malscore_index]["completed"])
            reports_path = path.join(REPORT_ROOT, "storage", "analyses", str(parent_task.id))
            if not path.exists(reports_path):
                shutil.copytree(report_path[max_malscore_index], reports_path)
                db.set_status(parent_task.id, TASK_REPORTED)
                log.info("Task #%d: reports generation completed (path=%s)", parent_task.id, reports_path)
            try:
                for sub_task in sub_tasks:
                    # TODO: delete negative task of mode==2
                    db.delete_task(sub_task.id)
                    db.delete_result(sub_task.id)
                    db.delete_sub_task(sub_task.id)
                    task_path = path.join(REPORT_ROOT, "storage", "analyses", str(sub_task.id))
                    if path.exists(task_path):
                        shutil.rmtree(task_path, True)
                log.info("Delete submitted tasks successfully")
            except Exception as e:
                log.info("Delete submitted tasks failed, msg: %s" % e)

    gc.collect()


def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def init_logging(debug=False):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    fh = logging.handlers.WatchedFileHandler(os.path.join(LOG_ROOT, "process.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def autoprocess(parallel=1):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()
    pool = multiprocessing.Pool(parallel, init_worker)
    pending_results = []

    try:
        # CAUTION - big ugly loop ahead.
        while count < maxcount or not maxcount:

            # Pending_results maintenance.
            for ar, tid, target, copy_path in list(pending_results):
                if ar.ready():
                    if ar.successful():
                        log.info("Task #%d: reports generation completed", tid)
                    else:
                        try:
                            ar.get()
                        except:
                            log.exception("Exception when processing task ID %u.", tid)
                            db.set_status(tid, TASK_FAILED_PROCESSING)

                    pending_results.remove((ar, tid, target, copy_path))

            # If still full, don't add more (necessary despite pool).
            if len(pending_results) >= parallel:
                time.sleep(5)
                continue

            # If we're here, getting parallel tasks should at least
            # have one we don't know.
            tasks = db.list_tasks(status=TASK_COMPLETED, limit=parallel, category="file",
                                  order_by="completed_on asc")
            added = False
            # For loop to add only one, nice. (reason is that we shouldn't overshoot maxcount)
            for task in tasks:
                # Not-so-efficient lock.
                if task.id in [tid for ar, tid, target, copy_path
                               in pending_results]:
                    continue

                if task.mode == 2 and task.id > 0:
                    continue

                log.info("Processing analysis data for Task #%d", task.id)

                if task.category == "file":
                    sample = db.view_sample(task.sample_id)

                    copy_path = os.path.join(REPORT_ROOT, "storage",
                                             "binaries", sample.sha256)
                else:
                    copy_path = None

                args = int(task.id), task.target, copy_path
                kwargs = dict(report=True, auto=True)
                result = pool.apply_async(process, args, kwargs)

                pending_results.append((result, task.id, task.target, copy_path))

                count += 1
                added = True
                break

            if not added:
                # don't hog cpu
                time.sleep(5)

    except KeyboardInterrupt:
        pool.terminate()
        raise
    except:
        import traceback
        traceback.print_exc()
    finally:
        pool.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str, help="ID of the analysis to process (auto for continuous processing of unprocessed tasks).")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    parser.add_argument("-p", "--parallel", help="Number of parallel threads to use (auto mode only).", type=int, required=False, default=1)
    args = parser.parse_args()

    init_logging(debug=args.debug)
    init_modules()

    if args.id == "auto":
        autoprocess(parallel=args.parallel)
    else:
        process(int(args.id), report=args.report)


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass