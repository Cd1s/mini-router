#!/usr/bin/env python3
import os
import unittest
from unittest import mock

import cdpshot


class ChromeDiscoveryTest(unittest.TestCase):
    def test_linux_chromium_is_selected(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            cdpshot.shutil, "which", side_effect=lambda name: "/usr/bin/chromium" if name == "chromium" else None
        ):
            self.assertEqual(cdpshot.find_chrome(), "/usr/bin/chromium")


if __name__ == "__main__":
    unittest.main()
