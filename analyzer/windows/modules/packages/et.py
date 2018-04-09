# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class ET(Package):
    """WPS Excel analysis package."""
    PATHS = [
        ("ProgramFiles", "WPS Office Personal", "office6", "et.exe"),
    ]

    def start(self, path):
        excel = self.get_path("Microsoft Office Excel")
        return self.execute(excel, "\"%s\" /e" % path, path)
