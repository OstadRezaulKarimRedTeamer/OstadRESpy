# -*- coding: utf-8 -*-
"""
====================================================================================================
               🛡️ OstadRESpy Engine 9: Air-Gapped Isolation & Disposable Sandbox Controller
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import tempfile
import shutil
import os

class IsolatedExecutionChamber:
    def __init__(self, target_file: str):
        self.target_file = target_file
        self.temp_dir = None

    def create_chamber(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ostadrespy_chamber_")
        target_name = os.path.basename(self.target_file)
        dest_path = os.path.join(self.temp_dir, target_name)
        shutil.copy2(self.target_file, dest_path)
        return dest_path

    def destroy_chamber(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass
