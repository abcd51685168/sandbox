# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class WPP(Package):
    """PowerPoint analysis package."""
    PATHS = [
        ("ProgramFiles", "WPS Office Personal", "office6", "wpp.exe"),
    ]

    def start(self, path):
        powerpoint = self.get_path("Microsoft Office PowerPoint")
        return self.execute(powerpoint, "\"%s\" /s" % path, path)
