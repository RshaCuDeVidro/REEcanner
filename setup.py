from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import subprocess
import os

class CustomBuild(build_py):
    def run(self):
        subprocess.check_call(['make'])
        super().run()

setup(
    name='reecanner',
    version='1.0.0',
    description='Fast TCP/UDP network scanner build with python and C worker, identify vulns with searchsploit. shodan like',
    author='rsha',
    packages=['reecanner'],
    package_data={'reecanner': ['worker.so', 'data/*']},
    include_package_data=True,
    install_requires=[
        'rich',
        'redis',
    ],
    entry_points={
        'console_scripts': [
            'reecanner=reecanner.__main__:main',
        ],
    },
    cmdclass={
        'build_py': CustomBuild,
    },
)
