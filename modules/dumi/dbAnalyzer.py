#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging

from lib.cuckoo.common.abstracts import Dumi
from lib.cuckoo.common.constants import UTILS_ROOT

log = logging.getLogger(__name__)

class DbAnalyzer(Dumi):
    order = 3

    def run(self):
        """return None or Signature"""
        self.key = "dbAnalyzer"
        result = []
        try:
            cmd_path = os.path.join(UTILS_ROOT, self.options.cmd_path)
            target = self.task["target"]
            if target.startswith("http://"):
                target = target[7:]
            elif target.startswith("https://"):
                target = target[8:]
            cmd = cmd_path + " --query-" + self.task["category"] + " " + target
            ret = os.popen(cmd)
            result = ret.read().strip('\n').split(" ")
        except Exception as e:
            log.error("Execute dbAnalyzer failed, %s" % e)
        return result
