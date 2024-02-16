from setuptools import setup, find_packages
from pip._internal.req import parse_requirements

requirements = [str(requirement.requirement) for requirement in list(parse_requirements("requirements.txt", session=False))]

with open('README.md', 'r', encoding='utf-8') as readable_file:
    long_description = readable_file.read()

setup(
    name='tn3w_utils',
    version='1.0.6',
    description='A consolidation of all tools created so far as a Python package',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TN3W',
    author_email='tn3wA8xxfuVMs2@proton.me',
    url='https://github.com/tn3w/tn3w_utils',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'tn3w_utils': ['languages.json']
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
    ],
    license='MIT',
    keywords=[],
    install_requires=requirements
)
