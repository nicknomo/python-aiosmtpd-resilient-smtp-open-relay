from setuptools import setup, find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
NEWS = open(os.path.join(here, 'NEWS.txt')).read()


version = '0.1'

install_requires = [
    'dnspython','aiosmtpd',
]


setup(name='resilientsmtprelay',
    version=version,
    description="Resilient aiosmtpd based open relay server",
    long_description=README + '\n\n' + NEWS,
    classifiers=[
      'Communications :: Email','Programming Language :: Python :: 3',
    ],
    keywords='AIOSmtpd email smtp relay HA high-availabilitiy',
    author='Nick Ross (CTC)',
    author_email='',
    url='https://github.com/nicknomo/python-aiosmtpd-simple-smtp-open-relay',
    license='MIT',
    packages=find_packages('resilientsmtprelay'),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
            'dnspython','aiosmtpd',
        ],
   
    }
)
