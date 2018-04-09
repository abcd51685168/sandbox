# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import shutil
import logging
import Queue
import json
from threading import Thread, Lock
import psutil
import codecs

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, REPORT_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_RUNNING, TASK_FAILED_PROCESSING
from lib.cuckoo.core.database import ANALYSIS_STARTED, ANALYSIS_FINISHED, TASK_FAILED_REPORTING
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.plugins import list_plugins, RunAuxiliary, RunProcessing, RunDumi
from lib.cuckoo.core.plugins import RunSignatures, RunReporting, GetFeeds, RunStaticScan
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.generate_result import generate_result
from lib.cuckoo.core.file_type import pd_fmt_file

try:
    import pefile
    import peutils

    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

log = logging.getLogger(__name__)

machinery = None
machine_lock = Lock()
latest_symlink_lock = Lock()

active_analysis_count = 0
# mp3:26009, mp4:27006, avi:27025
VM_NO_ANALYZE_TYPES = [26009, 27006, 27025]


class CuckooDeadMachine(Exception):
    """Exception thrown when a machine turns dead.

    When this exception has been thrown, the analysis task will start again,
    and will try to use another machine, when available.
    """
    pass


class AnalysisManager(Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task_id, error_queue):
        """@param task: task object containing the details for the analysis."""
        Thread.__init__(self)
        Thread.daemon = True

        self.errors = error_queue
        self.cfg = Config()
        self.storage = ""
        self.binary = ""
        self.machine = None
        self.db = Database()
        self.task = self.db.view_task(task_id)

    def init_storage(self):
        """Initialize analysis storage folder."""
        self.storage = os.path.join(REPORT_ROOT,
                                    "storage",
                                    "analyses",
                                    str(self.task.id))

        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if os.path.exists(self.storage):
            log.error("Analysis results folder already exists at path \"%s\","
                      " analysis aborted", self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Unable to create analysis folder %s", self.storage)
            return False

        return True

    def check_file(self):
        """Checks the integrity of the file to be analyzed."""
        sample = Database().view_sample(self.task.sample_id)

        sha256 = File(self.task.target).get_sha256()
        if sha256 != sample.sha256:
            log.error("Target file has been modified after submission: \"%s\"", self.task.target)
            return False

        return True

    def store_file(self):
        """Store a copy of the file being analyzed."""
        if not os.path.exists(self.task.target):
            log.error("The file to analyze does not exist at path \"%s\", "
                      "analysis aborted", self.task.target)
            return False

        sha256 = File(self.task.target).get_sha256()
        self.binary = os.path.join(REPORT_ROOT, "storage", "binaries", sha256)

        if os.path.exists(self.binary):
            log.info("Task: %d File already exists at \"%s\"" % (self.task.id, self.binary))
        else:
            # TODO: do we really need to abort the analysis in case we are not
            # able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                log.error("Unable to store file from \"%s\" to \"%s\", "
                          "analysis aborted", self.task.target, self.binary)
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            # if hasattr(os, "symlink"):
            #     os.symlink(self.binary, new_binary_path)
            # else:
            shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Unable to create symlink/copy from \"%s\" to "
                      "\"%s\": %s", self.binary, self.storage, e)

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire the a machine to run the analysis on.
        while True:
            machine_lock.acquire()

            # In some cases it's possible that we enter this loop without
            # having any available machines. We should make sure this is not
            # such case, or the analysis task will fail completely.
            if not machinery.availables():
                machine_lock.release()
                time.sleep(1)
                continue

            # If the user specified a specific machine ID, a platform to be
            # used or machine tags acquire the machine accordingly.
            try:
                machine = machinery.acquire(machine_id=self.task.machine,
                                            platform=self.task.platform,
                                            tags=self.task.tags)
            except CuckooOperationalError:
                continue
            finally:
                machine_lock.release()

            # If no machine is available at this moment, wait for one second
            # and try again.
            if not machine:
                log.debug("Task #%d: no machine available yet", self.task.id)
                time.sleep(1)
            else:
                log.info("Task #%d: acquired machine %s (label=%s)",
                         self.task.id, machine.name, machine.label)
                break

        self.machine = machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {}

        options["id"] = self.task.id
        options["ip"] = self.machine.resultserver_ip
        options["port"] = self.machine.resultserver_port
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["options"] = self.task.options
        options["enforce_timeout"] = self.task.enforce_timeout
        options["clock"] = self.task.clock
        options["terminate_processes"] = self.cfg.cuckoo.terminate_processes

        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()
            # if it's a PE file, collect export information to use in more smartly determining the right
            # package to use
            options["exports"] = ""
            if HAVE_PEFILE and ("PE32" in options["file_type"] or options["file_type"] == "MS-DOS executable"):
                try:
                    pe = pefile.PE(self.task.target)
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        exports = []
                        for exported_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            exports.append(re.sub(r'[^A-Za-z0-9_?@-]', '', exported_symbol.name))
                        options["exports"] = ",".join(exports)
                except:
                    pass

        return options

    def launch_analysis(self):
        """Start analysis."""
        succeeded = False
        dead_machine = False

        log.info("Starting analysis of %s \"%s\" (task=%d)",
                 self.task.category.upper(), self.task.target, self.task.id)

        # Initialize the analysis folders.
        if not self.init_storage():
            return False

        if self.task.category == "file":
            # Check whether the file has been changed for some unknown reason.
            # And fail this analysis if it has been modified.
            if not self.check_file():
                return False

            # Store a copy of the original file.
            if not self.store_file():
                return False

        # Acquire analysis machine.
        try:
            self.acquire_machine()
        except CuckooOperationalError as e:
            # log.error("Cannot acquire machine: {0}".format(e))
            return False

        Database().set_statistics_time(self.task.id, ANALYSIS_STARTED)
        # Generate the analysis configuration file.
        options = self.build_options()

        # At this point we can tell the ResultServer about it.
        try:
            Database().recruit_machine(self.task.id, self.machine.id)
            ResultServer().add_task(self.task, self.machine)
        except Exception as e:
            machinery.release(self.machine.label)
            self.errors.put(e)

        aux = RunAuxiliary(task=self.task, machine=self.machine)
        aux.start()

        try:
            # Mark the selected analysis machine in the database as started.
            guest_log = Database().guest_start(self.task.id,
                                               self.machine.name,
                                               self.machine.label,
                                               machinery.__class__.__name__)
            # Start the machine.
            machinery.start(self.machine.label)

            # Initialize the guest manager.
            guest = GuestManager(self.machine.name, self.machine.ip,
                                 self.machine.platform)

            # Start the analysis.
            guest.start_analysis(options)

            guest.wait_for_completion()
            succeeded = True
        except CuckooMachineError as e:
            # log.info(str(e), extra={"task_id": self.task.id})
            dead_machine = True
        except CuckooGuestError as e:
            log.debug(str(e), extra={"task_id": self.task.id})
        finally:
            # Stop Auxiliary modules.
            aux.stop()

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    dump_path = os.path.join(self.storage, "memory.dmp")
                    machinery.dump_memory(self.machine.label, dump_path)
                except NotImplementedError:
                    log.error("The memory dump functionality is not available "
                              "for the current machine manager.")
                except CuckooMachineError as e:
                    log.error(e)

            try:
                # Stop the analysis machine.
                machinery.stop(self.machine.label)
            except CuckooMachineError as e:
                log.warning("Unable to stop machine %s: %s",
                            self.machine.label, e)

            # Mark the machine in the database as stopped. Unless this machine
            # has been marked as dead, we just keep it as "started" in the
            # database so it'll not be used later on in this session.
            Database().guest_stop(guest_log)

            # After all this, we can make the ResultServer forget about the
            # internal state for this analysis task.
            ResultServer().del_task(self.task, self.machine)

            if dead_machine:
                # Remove the guest from the database, so that we can assign a
                # new guest when the task is being analyzed with another
                # machine.
                Database().guest_remove(guest_log)

                # Remove the analysis directory that has been created so
                # far, as launch_analysis() is going to be doing that again.
                shutil.rmtree(self.storage)

                # This machine has turned dead, so we throw an exception here
                # which informs the AnalysisManager that it should analyze
                # this task again with another available machine.
                raise CuckooDeadMachine()

            try:
                # Release the analysis machine. But only if the machine has
                # not turned dead yet.
                machinery.release(self.machine.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. "
                          "You might need to restore it manually.",
                          self.machine.label, e)
        Database().set_statistics_time(self.task.id, ANALYSIS_FINISHED)

        return succeeded

    def process_results(self):
        """Process the analysis results and generate the enabled reports."""
        # This is the results container. It's what will be used by all the
        # reporting modules to make it consumable by humans and machines.
        # It will contain all the results generated by every processing
        # module available. Its structure can be observed through the JSON
        # dump in the analysis' reports folder. (If jsondump is enabled.)
        results = {}
        GetFeeds(results=results).run()
        RunProcessing(task_id=self.task.id, results=results).run()
        RunSignatures(task_id=self.task.id, results=results).run()

        try:
            log.info("Task #%d: start to generate report" % self.task.id)
            report_result = generate_result(self.task, results)
            RunReporting(task_id=self.task.id, results=report_result).run()
            Database().set_status(self.task.id, TASK_REPORTED)
        except Exception as e:
            log.error("#%s generate report failed, msg:%s" % (self.task.id, e))
            self.db.set_status(self.task.id, TASK_FAILED_REPORTING)

        # If the target is a file and the user enabled the option,
        # delete the original copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_original and self.task.id > 0:
            if not os.path.exists(self.task.target):
                log.warning("Original file does not exist anymore: \"%s\": "
                            "File not found.", self.task.target)
            else:
                try:
                    os.remove(self.task.target)
                except OSError as e:
                    log.error("Unable to delete original file at path "
                              "\"%s\": %s", self.task.target, e)

        # If the target is a file and the user enabled the delete copy of
        # the binary option, then delete the copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_bin_copy and self.task > 0:
            if not os.path.exists(self.binary):
                log.warning("Copy of the original file does not exist anymore: \"%s\": File not found", self.binary)
            else:
                try:
                    os.remove(self.binary)
                except OSError as e:
                    log.error("Unable to delete the copy of the original file at path \"%s\": %s", self.binary, e)

        log.info("Task #%d: reports generation completed (path=%s)", self.task.id, self.storage)

        return True

    def _set_task_completed(self):
        reports_path = os.path.join(REPORT_ROOT, "storage", "analyses", str(self.task.id), "reports")
        if not os.path.exists(reports_path):
            os.makedirs(reports_path)
        self.db.set_status(self.task.id, TASK_COMPLETED)
        log.info("Task #%d: analysis procedure completed", self.task.id)

    def run(self):
        """Run manager thread."""
        sample = self.db.view_sample(self.task.sample_id)
        if sample:
            filesize = sample.file_size
            if filesize < 100 * 1024 * 1024:
                results = {}
                results = RunDumi(task_id=self.task.id, results=results).run()
                RunStaticScan(task_id=self.task.id, results=results).run()
                for key, value in results.items():
                    if isinstance(value, list):
                        value = value[0]
                    self.db.add_result(self.task.id, key, desc_en=value)
                log.info("#%d Result of %s[%s]: %s" % (self.task.id, self.task.category, self.task.target, results))

        if self.task.mode == 0:
            task_results = self.db.list_results(self.task.id)
            scan_flag = False
            for result in task_results:
                # {'yara': None, 'dbAnalyzer': ['0'], 'clamav': None}
                if result.desc_en not in [None, '0']:
                    scan_flag = True
                    break
            if scan_flag or not self.cfg.cuckoo.enabled:
                log.debug("#%d static scan detects virus or sandbox is off." % self.task.id)
                self._set_task_completed()
                return
        task_type = pd_fmt_file(self.task.target.encode("utf-8"))[0]
        if task_type in VM_NO_ANALYZE_TYPES:
            log.debug("#%d sample'type[%d] does not support vm analysis yet." % (self.task.id, task_type))
            self._set_task_completed()
            return

        # 64_bit PE file is not supported for now.
        tags = [tag.name for tag in self.task.tags]
        if "64_bit" in tags:
            log.debug("#%d 64_bit does not support vm analysis yet." % self.task.id)
            self._set_task_completed()
            return

        global active_analysis_count
        active_analysis_count += 1
        try:
            while True:
                try:
                    success = self.launch_analysis()
                except CuckooDeadMachine:
                    continue

                break

            Database().set_status(self.task.id, TASK_COMPLETED)

            log.debug("Released database task #%d with status %s",
                      self.task.id, success)

            if self.cfg.cuckoo.process_results:
                self.process_results()
            log.info("Task #%d: analysis procedure completed", self.task.id)
        except:
            log.exception("Failure in AnalysisManager.run")

        active_analysis_count -= 1


class Scheduler:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self, maxcount=None):
        self.running = True
        self.cfg = Config()
        self.db = Database()
        self.maxcount = maxcount

    def initialize(self):
        """Initialize the machine manager."""
        global machinery

        machinery_name = self.cfg.cuckoo.machinery

        log.info("Using \"%s\" machine manager", machinery_name)

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinery")[0]
        # Initialize the machine manager.
        machinery = plugin()

        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery_name)

        if not os.path.exists(conf):
            raise CuckooCriticalError("The configuration file for machine "
                                      "manager \"{0}\" does not exist at path:"
                                      " {1}".format(machinery_name, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        machinery.set_options(Config(machinery_name))

        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError("Error initializing machines: %s" % e)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        self.machine_count = len(machinery.machines())
        if not len(machinery.machines()):
            raise CuckooCriticalError("No machines available.")
        else:
            log.info("Loaded %s machine/s", len(machinery.machines()))

        if len(machinery.machines()) > 1 and self.db.engine.name == "sqlite":
            log.warning("As you've configured Cuckoo to execute parallel "
                        "analyses, we recommend you to switch to a MySQL "
                        "a PostgreSQL database as SQLite might cause some "
                        "issues.")

        if len(machinery.machines()) > 4 and self.cfg.cuckoo.process_results:
            log.warning("When running many virtual machines it is recommended "
                        "to process the results in a separate process.py to "
                        "increase throughput and stability. Please read the "
                        "documentation about the `Processing Utility`.")

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        machinery.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks.")

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = Queue.Queue()

        # Command-line overrides the configuration file.
        if self.maxcount is None:
            self.maxcount = self.cfg.cuckoo.max_analysis_count

        min_idle_cpu = self.cfg.cuckoo.idle_cpu
        # This loop runs forever.
        while self.running:
            time.sleep(0.1)
            if min_idle_cpu:
                idle_cpu = psutil.cpu_times_percent().idle
                if idle_cpu < float(min_idle_cpu):
                    log.debug("idle_cpu[%s] is lower than threshold[%s], assign no task for now"
                              % (idle_cpu, min_idle_cpu))
                    time.sleep(1)
                    continue
            if self.db.count_tasks1(TASK_RUNNING) >= self.machine_count:
                time.sleep(1)
                continue

            # (id,target,category,mode)
            task = self.db.fetch_pending_task1()
            if task:
                # {'category': 'file', 'mode': 1, 'id': 103, 'target': '/tmp/2015.3.3/004.exe'}
                keys = ("id", "target", "category", "mode")
                task = dict(zip(keys, task))
                # scan md5/ip/domain
                if task["category"] in ["ip", "domain", "md5", "url"]:
                    log.info("#%d Start to scan %s" % (task["id"], task["target"]))
                    try:
                        results = {}
                        result = RunDumi(task_id=task["id"], results=results).run()
                        self.db.set_status(task_id=task["id"], status=TASK_COMPLETED)
                        log.info("#%d Result of %s[%s]: %s" % (task["id"], task["category"], task["target"], result))
                        report_result = generate_result(task, result)
                    except Exception as e:
                        log.error("scan %s:%s failed, msg:%s" % (task["category"], task["target"], e))
                        self.db.set_status(task["id"], TASK_FAILED_ANALYSIS)
                        continue

                    try:
                        reports_path = os.path.join(REPORT_ROOT, "storage", "analyses", str(task["id"]), "reports")
                        if not os.path.exists(reports_path):
                            os.makedirs(reports_path)
                        path = os.path.join(reports_path, "report.json")
                        with codecs.open(path, "w", "utf-8") as report:
                            json.dump(report_result, report, ensure_ascii=False, sort_keys=False,
                                      indent=4, encoding="utf-8")
                        log.info("Task #%d: analysis procedure completed", task["id"])
                        Database().set_status(task["id"], TASK_REPORTED)
                    except Exception as e:
                        log.error("#%s generate report failed, msg:%s" % (task["id"], e))
                        self.db.set_status(task["id"], TASK_FAILED_REPORTING)
                        continue

                # static scan file
                elif task["category"] in "file":
                    log.debug("get cuckoo task:%s" % task)
                    # Initialize and start the analysis manager.
                    analysis = AnalysisManager(task["id"], errors)
                    analysis.start()
                else:
                    self.db.set_status(task["id"], TASK_FAILED_ANALYSIS)

            # Deal with errors.
            try:
                raise errors.get(block=False)
            except Queue.Empty:
                pass
