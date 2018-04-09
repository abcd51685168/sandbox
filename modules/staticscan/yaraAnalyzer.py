#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from lib.cuckoo.common.abstracts import StaticScan
from lib.cuckoo.common.constants import CONTENT_ROOT

log = logging.getLogger(__name__)
RULE_PATH = os.path.join(CONTENT_ROOT, "yara/rules")

try:
    import yara
    f = "all.yar"
    log.debug('Compile %s' % os.path.join(RULE_PATH, f))
    rules = yara.compile(os.path.join(RULE_PATH, f))
except Exception as e:
    log.exception('could not import yara or compile yara rules: %s' % e)
    raise EnvironmentError('could not import yara or compile yara rules')


class YaraAnalyzer(StaticScan):
    order = 2

    def run(self):
        """return None or Signature"""
        self.key = 'yara'
        try:
            matches = rules.match(self.task["target"])
        except:
            log.exception('Task #%d yara scan error' % self.task["id"])
            return None

        return matches[0].rule if matches else None
