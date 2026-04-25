"""
Core package for the D3FENDer application. Here is located all the source codes, split up into
separate packages that fit their desired purposes. This package and its subpackages contain
all the source code required for the app to execute its desired purposes.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("d3fender")
except PackageNotFoundError:
    __version__ = "0.0.0" # If fails.
