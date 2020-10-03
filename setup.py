import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hvac-openpgp",
    version="0.0.2",
    author="Trishank Karthik Kuppusamy",
    author_email="trishank.kuppusamy@datadoghq.com",
    description="A Transit-Secrets-Engine-like API for vault-gpg-plugin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trishankatdatadog/hvac-openpgp",
    packages=setuptools.find_packages(
        exclude=("docs", "scripts", "tests",)
    ),
    install_requires=(
        "hvac>=0.10.5",
    ),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
