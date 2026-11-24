#!/usr/bin/env python3
"""Convenient CLI entry point; actual implementation lives in server/."""
from pathlib import Path
import runpy
import sys

server_directory = Path(__file__).resolve().parent / 'server'
sys.path.insert(0, str(server_directory))
runpy.run_path(str(server_directory / 'server.py'), run_name='__main__')
