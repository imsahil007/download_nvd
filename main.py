

#!/usr/bin/python3
# pylint: disable=invalid-name, useless-object-inheritance
# useless-object-inheritance kept for python2 compatibility

"""
This tool downloads CVE data after every 24 hours.
"""

import os
import sys

from download_nvd.cvedb import CVEDB

from download_nvd.log import LOGGER





def main(argv=None):
    """ Scan a binary file for certain open source libraries that may have CVEs """
    cvedb_orig = CVEDB(
        version_check=False
    )
    cvedb_orig.clear_cached_data()
    cvedb_orig.refresh_cache_and_update_db()
   

if __name__ == "__main__":
    if os.getenv("NO_EXIT_CVE_NUM"):
        main()
    else:
        sys.exit(main())
