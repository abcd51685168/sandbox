#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil
import logging

from lib.cuckoo.common.abstracts import StaticScan
log = logging.getLogger(__name__)

try:
    import clamd
    clamav = clamd.ClamdUnixSocket()
    clamav.ping()
except Exception as e:
    log.exception("could not import clamd or connect clamd server by unix socket :%s" % e)
    raise EnvironmentError('could not import clamd or connect clamd server by unix socket: %s' % e)


class ClamavAnalyzer(StaticScan):
    order = 1

    def run(self):
        """return None or Signature"""
        self.key = "clamav"
        try:
            task_tmp_dir = '/tmp/scan'
            if not os.path.exists(task_tmp_dir):
                os.mkdir(task_tmp_dir)

            task_tmp_dir = os.path.join(task_tmp_dir, str(self.task["id"]))
            # log.debug('Task #d%: Temp dir %s' % (self.task["id"], task_tmp_dir))
            if not os.path.exists(task_tmp_dir):
                os.mkdir(task_tmp_dir)

            dest_file_path = os.path.join(task_tmp_dir, os.path.basename(self.task["target"]))
            # log.debug('Task #d%: Dest file path %s' % dest_file_path)
            shutil.copy(self.task["target"], task_tmp_dir)
            result = clamav.scan(dest_file_path)

            shutil.rmtree(task_tmp_dir)
        except Exception as e:
            log.exception('Exception clamav scan: %s' % e)
            # log.exception('Exception clamav scan => %s' % self.task.target.encode('utf-8'))
            return None
        #result sample: {u'/run/shm/tmp_2998710558886437521_http_1.js': (u'OK', None)}
        # TODO: solve error:Can't create temporary directory
        # reference:(https://wiki.archlinux.org/index.php/ClamAV#Error:_Can.27t_create_temporary_directory)
        # {u'/tmp/test.pdf': (u'ERROR', u"Can't create temporary directory")}
        #result sample: {u'/run/shm/tmp_2998710558886437521_http_1.js': (u'FOUND', u"Trojan_Spy_Zbot_436")}
        log.debug("Task #%d clamav result: %s" % (self.task["id"], result))
        if not result:
            return None
        found = result.values()[0][0]
        name = result.values()[0][1]
        if found in "FOUND":
            return name
        elif found in "ERROR":
            log.error("Task #%d check permissions of the binary folder, every parent folder should be with x "
                      "permission, %s" % (self.task["id"], name))
            return None
        elif found in "OK":
            return None
