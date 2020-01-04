from setuptools import setup, find_packages
import re

with open('requirements.txt') as f:
    requirements = f.readlines()

setup(name='redhat',
      author='CapnS',
      url='https://github.com/CapnS/RedHatCVE',
      version='1.0.0a',
      packages=['redhat'],
      license='GPL-3.0',
      description='A python wrapper for the Red Hat CVE API',
      include_package_data=True,
      install_requires=requirements,
      python_requires='>=3.6.0',
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GPL-3.0 License',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
      ]
)
