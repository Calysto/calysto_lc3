import io
import sys

from setuptools import find_packages, setup

with io.open('calysto_lc3/_version.py', encoding="utf-8") as fid:
    for line in fid:
        if line.startswith('__version__'):
            __version__ = line.strip().split()[-1][1:-1]
            break

with open('README.md') as f:
    readme = f.read()

setup(name='calysto_lc3',
      version=__version__,
      description='An LC-3 Assembly Language kernel for Jupyter based on MetaKernel',
      long_description=readme,
      author='Douglas Blank',
      author_email='doug.blank@gmail.com',
      url="https://github.com/Calysto/calysto_lc3",
      install_requires=["metakernel"],
      packages=find_packages(include=["calysto_lc3", "calysto_lc3.*"]),
      package_data={'calysto_lc3': ["images/*.png"]},
      classifiers = [
          'Framework :: IPython',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 2',
          'Programming Language :: Lisp',
          'Topic :: System :: Shells',
      ]
)
