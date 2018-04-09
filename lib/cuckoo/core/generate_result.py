#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import logging
from datetime import datetime

from lib.cuckoo.core.database import Database, Task
from lib.cuckoo.common.objects import File
from lib.cuckoo.core.file_type import pd_fmt_file
from lib.cuckoo.common.constants import UTILS_ROOT

sys.path.append(os.path.join(UTILS_ROOT, "..", "assessment"))
from assessment import assessment

log = logging.getLogger(__name__)


def generate_result(task, results=None):
    # task : {'category': 'file', 'mode': 1, 'id': 103, 'target': '/tmp/2015.3.3/004.exe'}
    query_info = {}
    query_result = {}
    report_result = {}
    if isinstance(task, Task):
        class_task = task
        task = {"id": task.id, "target": task.target, "category": task.category}
    elif isinstance(task, dict):
        class_task = Database().view_task(task["id"])

    try:
        started = class_task.started_on
        completed = class_task.completed_on
        duration = (completed - started).seconds
        if completed.microsecond < started.microsecond:
            duration += 1
        started = started.strftime("%Y-%m-%d %H:%M:%S")
        completed = completed.strftime("%Y-%m-%d %H:%M:%S")
        log.debug("started_time:%s completed_time:%s duration:%s" % (started, completed, duration))
    except:
        log.critical("Failed to get start/end time from Task.")
        duration = -1

    if task["category"] in ["ip", "domain", "md5", "url"]:
        # {'domain': {'wbAnalyzer': ['1', '23', '50']}}
        # {'domain': {'wbAnalyzer': ['0']}}
        # {'domain': {'ccdmAnalyzer': ['1']}}
        # {'domain': {'ccdmAnalyzer': ['0']}}
        # {'domain': {'dbAnalyzer': ['1', '23', '50']}}
        #
        # {'ip': {'wbAnalyzer': ['1', '23', '50']}}
        # {'ip': {'wbAnalyzer': ['0']}}
        # {'ip': {'dbAnalyzer': ['1', '23', '50']}}
        # {'ip': {'dbAnalyzer': ['0', '0', '0']}}
        #
        # {'md5': {'wbAnalyzer': ['1']}}
        # {'md5': {'wbAnalyzer': ['0']}}
        # {'md5': {'dbAnalyzer': ['1']}}
        # {'md5': {'dbAnalyzer': ['0']}}
        query_info = {task["category"]: results}
        log.info("Task#%d => query_info: %s" % (task["id"], query_info))
        query_result = assessment(query_info)
        str_sha1 = File().get_str_sha1(task["target"])

        report_result = {"category": task["category"], "targetdetail": {"target": task["target"], "sha1": str_sha1},
                         "reporttime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                         }
        report_result.update(query_result)
        # pretty_query_result = json.dumps(report_result, ensure_ascii=False, indent=4, separators=(',', ': '))
        query_result_encoding = json.dumps(report_result, ensure_ascii=False)
        log.debug("Task#%d => query_result: %s" % (task["id"], query_result_encoding))
        return report_result

    elif task["category"] in "file":
        #{'yara': [u'Trojan_Fakealert_1'],
        # 'clamav': [None],
        # 'cuckoo': ['reads_self', 'stealth_timeout', 'persistence_autorun', 'virus', 9.100000000000001],
        # /'cuckoo': [None]
        # 'md5': {u'dbAnalyzer': u'0'}}
        task_results = Database().list_results(task["id"])
        # Database().delete_result(task.id)

        query_info = {}
        for result in task_results:
            if result.engine in ["dbAnalyzer", "wbAnalyzer"]:
                query_info["md5"] = {result.engine: result.desc_en}
                continue
            if result.engine in query_info and query_info[result.engine]:
                query_info[result.engine] = query_info[result.engine].append(result.desc_en)
            else:
                query_info[result.engine] = [result.desc_en]
        if results:
            if results["signatures"]:
                query_info["cuckoo"] = [sig["name"] for sig in results["signatures"]]
                query_info["cuckoo"].append(results["malscore"])
            else:
                query_info["cuckoo"] = [None]

        targetdetail = {}
        if os.path.exists(task["target"]):
            filedetail = File(task["target"]).get_all()
            fmt_file = pd_fmt_file(task["target"].encode("utf-8"))
            targetdetail = {
                "target": filedetail["name"], "size": filedetail["size"], "extnomatch": 1 - fmt_file[1],
                "type": fmt_file[2], "md5": filedetail["md5"], "sha1": filedetail["sha1"]
            }
        report_result = {
            "category": task["category"], "targetdetail": targetdetail,
            "reporttime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "started": started,
            "completed": completed, "duration": duration
        }

        log.info("Task#%d => query_info: %s" % (task["id"], query_info))
        query_result = assessment(query_info)
        report_result.update(query_result)
        # pretty_query_info = json.dumps(query_info, ensure_ascii=False, indent=4, separators=(',', ': '))
        # pretty_query_result = json.dumps(report_result, ensure_ascii=False, indent=4, separators=(',', ': '))
        query_result_encoding = json.dumps(report_result, ensure_ascii=False)
        log.debug("Task#%d => query_result: %s" % (task["id"], query_result_encoding))
        if results:
            if "signatures" in results:
                sandbox_details = query_result["details"]["sandbox"]
                for signature in results["signatures"]:
                    for sandbox_detail in sandbox_details:
                        if signature["name"] == sandbox_detail["name"]:
                            signature["description_cn"] = sandbox_detail["desc_cn"]
            cuckoo_result = {"sandbox_result": results}
            report_result.update(cuckoo_result)
        return report_result
