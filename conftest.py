import sys
import os

# Make the package importable when running pytest from the repo root
# without requiring `pip install -e .`
sys.path.insert(0, os.path.dirname(__file__))
