110525 - Version 121-1:
-fix async summary report bug (duration should be =/ ndev)

110406 - Version 121:
- Add exit on end of file option
- Multi threaded validation mode support (-T nthread with -C)
- Fix for random IO rate != 0 or 100 (didn't work - buf inserted in version 120)
- For option -C and -m: if a single taget file is used, the parameter is the path not the base
- Fix wrong message when opening a meta data file (was "joining" even if ref was zero)
- Fix option -o offset (didn't work - buf inserted in version 120)
- Update docs

110327 - Version 120: (1.2):
- Major cleanup
- AIO stats fixes
- Verification modes

This binary was compiled on RHEL6 x64 and requires libaio. In it doesn't work for you system try to compile it yourself.
