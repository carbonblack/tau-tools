# setup.py
# NOTE: Not currently working due to puremagic's json not being pulled in

from distutils.core import setup
import py2exe

missing_files = [ ('puremagic', ['c:\python27\Lib\site-packages\puremagic\magic_data.json'] ) ]

setup(
        console=['pseudo_ransomware.py'],
        data_files = missing_files,
        options = {
            'py2exe': {
                'packages' : ['puremagic'],
                'bundle_files' : 1,
                }
            }
)
