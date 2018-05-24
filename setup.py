from setuptools import setup

url = ""
version = "0.1.0"
readme = open('README.md').read()

setup(
    name="encrypting_tarball",
    packages=["encrypting_tarball"],
    version=version,
    description="A simple method for password protecting directories in tarballs using cryptographic checksums for validation",
    long_description=readme,
    include_package_data=True,
    author="Aaron Watters",
    author_email="awatters@flatironinstitute.org",
    url=url,
    install_requires=[],
    download_url="{}/tarball/{}".format(url, version),
    license="MIT"
)
