from setuptools import setup
import os

__version__ = "0.1.0"  # Starting version for your fork
with open("cipy/_version.py") as f:
    exec(f.read())


def read(file_name):
    return open(os.path.join(os.path.dirname(__file__), file_name)).read()


setup(
    name="cipy",
    version=__version__,
    author="[Your Name]",
    author_email="[your-email@example.com]",
    url="https://github.com/[your-username]/cipy",
    description="A Python library for CIP and EtherNet/IP communication with industrial devices.",
    long_description=read("README.rst"),
    license="MIT",
    packages=["cipy", "cipy.packets", "cipy.cip"],
    package_data={"cipy": ["py.typed"]},
    python_requires=">=3.6.1",
    include_package_data=True,
    extras_require={
        "tests": ["pytest"]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Manufacturing",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",  # Added for modern support
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Scientific/Engineering :: Human Machine Interfaces",
    ],
)

# Build and Publish Commands:
#
# python -m build
# twine upload --skip-existing dist/*
