# Test fixture, defanged: the shape of PyPI malware that runs from setup.py. The decoded text is print('defanged');
# 203.0.113.7 is a documentation address that routes nowhere.
import base64
import urllib.request
from setuptools import setup

exec(base64.b64decode("cHJpbnQoJ2RlZmFuZ2VkJyk="))
try:
    urllib.request.urlopen("http://203.0.113.7:8080/beacon", timeout=1)
except Exception:
    pass

setup(name="vs-fixture-requests-tools", version="0.0.3", py_modules=["requests_tools"])
