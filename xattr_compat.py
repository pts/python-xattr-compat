#! /usr/bin/python2.4
# by pts@fazekas.hu at Sat Apr  9 14:20:09 CEST 2011

"""Portable Python module to query and set POSIX extended attributes of files.

This Python module is a wrapper around the xattr Python package, but if
xattr is not available, compatible replacement implementations are provided
for some systems (currently Linux), so we have a pure Python implementation
for extended attribute manipulations.

This module can use several implementation backends, selected automatically,
in this order:

* xattr: the xattr Python package (not built-in). This is portable across
  operating systems (e.g. Linux, Mac OS X, FreeBSD).
* dl: the built-in dl Python module for Linux i386
* ctypes: the ctypes Python module for Linux, built into Python 2.6 or later

This module should be compatible with Python 2.4 and above. This doesn't mean
that it works with all installations of Python 2.4 and above, see the list of
implementation backends above.

The actual backend used is available in the module attribute named IMPL.

Functions provided:

* listxattr: List names of extended attributes a file has. (llistxattr(2) can
  be enabled as an argument.)
* flistxattr: List names of extended attributes an open file has.
* getxattr: Get the value of an extended attribute of a file. (llistxattr(2)
  can be enabled as an argument.)
* fgetxattr: Get the value of an extended attribute of an open file.
* setxattr: Set the value of an extended attribute of a file. (lsetxattr(2)
  can be enabled as an argument.)
* fsetxattr: Set the value of an extended attribute of an open file.
* removexattr: Remove an extended attribute from a file.
* fremovexattr: Remove an extended attribute from an open file.

TODO(pts): Add Mac OS X support with /tmp/xattr.py
TODO(pts): Test the ctypes implementation on amd64.
TODO(pts): Support XATTR_CREATE and XATTR_REPLACE flags for setxattr.
"""

__author__ = 'pts@fazekas.hu (Peter Szabo)'

import errno
import os
import sys

IMPL = None

# Try to use the xattr extension module.
xattr = None
if IMPL is None:
  try:
    import xattr
    if getattr(xattr, '__version__', '') < '0.2.2':
      # Earlier versions are buggy, don't use them (rdiff-backup needs 0.2.2).
      xattr = None
  except ImportError:
    pass
  if xattr:
    IMPL = 'xattr'
    XATTR_ENODATA = getattr(errno, 'ENODATA', -1)
    XATTR_ENOATTR = getattr(errno, 'ENOATTR', -1)

    def getxattr(filename, attr_name, do_not_follow_symlinks=False):
      try:
        return xattr._xattr.getxattr(
            filename, attr_name, 0, 0, do_not_follow_symlinks)
      except IOError, e:
        if e[0] != XATTR_ENODATA:
          # We convert the IOError raised by the _xattr module to OSError
          # expected from us.
          raise OSError(e[0], e[1])
        return None

    def fgetxattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      try:
        return xattr._xattr.fgetxattr(fd, attr_name)
      except IOError, e:
        if e[0] != XATTR_ENODATA:
          raise OSError(e[0], e[1])
        return None

    def setxattr(filename, attr_name, value, do_not_follow_symlinks=False):
      try:
        return xattr._xattr.setxattr(
            filename, attr_name, value, 0, do_not_follow_symlinks)
      except IOError, e:
        raise OSError(e[0], e[1])

    def fsetxattr(fd, attr_name, value):
      if not isinstance(fd, int):
        fd = fd.fileno()
      try:
        return xattr._xattr.fsetxattr(fd, attr_name, value)
      except IOError, e:
        raise OSError(e[0], e[1])

    def removexattr(filename, attr_name, do_not_follow_symlinks=False):
      try:
        return xattr._xattr.removexattr(
            filename, attr_name, do_not_follow_symlinks)
      except IOError, e:
        # On some systems, we don't get ENOATTR, but this just succeeds
        # even if attr_name did not exist.
        if e[0] != XATTR_ENOATTR:
          raise OSError(e[0], e[1])

    def fremovexattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      try:
        return xattr._xattr.fremovexattr(fd, attr_name)
      except IOError, e:
        if e[0] != XATTR_ENOATTR:
          raise OSError(e[0], e[1])

    def listxattr(filename, do_not_follow_symlinks=False):
      # Please note that xattr.listxattr returns a tuple of unicode objects,
      # so we have to call xattr._xattr.listxattr to get the str objects.
      try:
        data = xattr._xattr.listxattr(filename, do_not_follow_symlinks)
      except IOError, e:
        raise OSError(e[0], e[1])
      if data:
        assert data[-1] == '\0'
        data = data.split('\0')
        data.pop()  # Drop last empty string because of the trailing '\0'.
        return data
      else:
        return []

    def flistxattr(fd):
      if not isinstance(fd, int):
        fd = fd.fileno()
      try:
        data = xattr._xattr.flistxattr(fd)
      except IOError, e:
        raise OSError(e[0], e[1])
      if data:
        assert data[-1] == '\0'
        data = data.split('\0')
        data.pop()  # Drop last empty string because of the trailing '\0'.
        return data
      else:
        return []

# Try to use dl (Python <=2.4) for Linux i386.
dl = None
if IMPL is None:
  try:
    import dl
  except ImportError:
    pass
  if dl:
    LIBC_DL = dl.open('libc.so.6')
    for name in ('memcpy', '__errno_location', 'llistxattr', 'listxattr',
                 'lgetxattr', 'getxattr'):
      if LIBC_DL.sym(name) is None:
        dl = LIBC_DL = None
        break
  if dl:
    import struct
    IMPL = 'dl'
    INT_SIZE = len(struct.pack('i', 0))  # Should be 4, but we play it safe.
    DL_ENOATTR = getattr(errno, 'ENOATTR', -1)  # Not on Linux.

    # TODO(pts): Test this in multithreaded applications.

    def getxattr(filename, attr_name, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __getxattr_low(filename, attr_name, 'lgetxattr')
      else:
        return __getxattr_low(filename, attr_name, 'getxattr')

    def fgetxattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __getxattr_low(fd, attr_name, 'fgetxattr')

    def __getxattr_low(file_id, attr_name, getxattr_name):
      errno_loc = LIBC_DL.call('__errno_location')
      err_str = 'X' * INT_SIZE
      value = 'x' * 256
      got = LIBC_DL.call(getxattr_name, file_id, attr_name, value, len(value))
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
        err = struct.unpack('i', err_str)[0]
        if err == errno.ENODATA:
          # The file exists, but doesn't have the specified xattr.
          return None
        elif err != errno.ERANGE:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        got = LIBC_DL.call(getxattr_name, file_id, attr_name, None, 0)
        if got < 0:
          LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
          err = struct.unpack('i', err_str)[0]
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        assert got > len(value)
        value = 'x' * got
        # We have a race condition here, someone might have changed the xattr
        # by now.
        got = LIBC_DL.call(getxattr_name, file_id, attr_name, value, got)
        if got < 0:
          LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
          err = struct.unpack('i', err_str)[0]
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        return value
      assert got <= len(value)
      return value[:got]

    def setxattr(filename, attr_name, value, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __setxattr_low(filename, attr_name, value, 'lsetxattr')
      else:
        return __setxattr_low(filename, attr_name, value, 'setxattr')

    def fsetxattr(fd, attr_name, value):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __setxattr_low(fd, attr_name, value, 'fsetxattr')

    def __setxattr_low(file_id, attr_name, value, setxattr_name):
      errno_loc = LIBC_DL.call('__errno_location')
      err_str = 'X' * INT_SIZE
      value = str(value)
      got = LIBC_DL.call(setxattr_name, file_id, attr_name, value, len(value), 0)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), file_id))

    def removexattr(filename, attr_name, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __removexattr_low(filename, attr_name, 'lremovexattr')
      else:
        return __removexattr_low(filename, attr_name, 'removexattr')

    def fremovexattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __removexattr_low(fd, attr_name, 'fremovexattr')

    def __removexattr_low(file_id, attr_name, removexattr_name):
      errno_loc = LIBC_DL.call('__errno_location')
      err_str = 'X' * INT_SIZE
      got = LIBC_DL.call(removexattr_name, file_id, attr_name)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
        err = struct.unpack('i', err_str)[0]
        if err != DL_ENOATTR:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))

    def listxattr(filename, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __listxattr_low(filename, 'llistxattr')
      else:
        return __listxattr_low(filename, 'listxattr')

    def flistxattr(fd):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __listxattr_low(fd, 'flistxattr')

    def __listxattr_low(file_id, listxattr_name):
      errno_loc = LIBC_DL.call('__errno_location')
      err_str = 'X' * INT_SIZE
      value = 'x' * 256
      got = LIBC_DL.call(listxattr_name, file_id, value, len(value))
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
        err = struct.unpack('i', err_str)[0]
        if err != errno.ERANGE:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        got = LIBC_DL.call(listxattr_name, file_id, None, 0)
        if got < 0:
          LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
          err = struct.unpack('i', err_str)[0]
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        assert got > len(value)
        value = 'x' * got
        # We have a race condition here, someone might have changed the xattr
        # by now.
        got = LIBC_DL.call(listxattr_name, file_id, value, got)
        if got < 0:
          LIBC_DL.call('memcpy', err_str, errno_loc, INT_SIZE)
          err = struct.unpack('i', err_str)[0]
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
      if got:
        assert got <= len(value)
        assert value[got - 1] == '\0'
        return value[:got - 1].split('\0')
      else:
        return []

# Try to use ctypes (from Python 2.6) for Linux.
ctypes = None
if IMPL is None:
  try:
    import ctypes
  except ImportError:
    ctypes = None
  if ctypes:
    LIBC_CTYPES = ctypes.CDLL('libc.so.6', use_errno=True)
    for name in ('llistxattr', 'listxattr', 'lgetxattr', 'getxattr'):
      if not hasattr(LIBC_CTYPES, name):
        ctypes = LIBC_CTYPES = None
        break
  if ctypes:
    IMPL = 'ctypes'
    CTYPES_ENOATTR = getattr(errno, 'ENOATTR', -1)  # Not on Linux.

    def getxattr(filename, attr_name, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __getxattr_low(filename, attr_name, LIBC_CTYPES.lgetxattr)
      else:
        return __getxattr_low(filename, attr_name, LIBC_CTYPES.getxattr)

    def fgetxattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __getxattr_low(fd, attr_name, LIBC_CTYPES.fgetxattr)

    def __getxattr_low(file_id, attr_name, getxattr_func):
      value = 'x' * 256
      got = getxattr_func(file_id, attr_name, value, len(value))
      if got < 0:
        err = ctypes.get_errno()
        if err == errno.ENODATA:
          # The file exists, but doesn't have the specified xattr.
          return None
        elif err != errno.ERANGE:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        got = getxattr_func(file_id, attr_name, None, 0)
        if got < 0:
          err = ctypes.get_errno()
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        assert got > len(value)
        value = 'x' * got
        # We have a race condition here, someone might have changed the xattr
        # by now.
        got = getxattr_func(file_id, attr_name, value, got)
        if got < 0:
          err = ctypes.get_errno()
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        return value
      assert got <= len(value)
      return value[:got]

    def setxattr(filename, attr_name, value, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __setxattr_low(filename, attr_name, value, LIBC_CTYPES.lsetxattr)
      else:
        return __setxattr_low(filename, attr_name, value, LIBC_CTYPES.setxattr)

    def fsetxattr(fd, attr_name, value):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __setxattr_low(fd, attr_name, value, LIBC_CTYPES.fsetxattr)

    def __setxattr_low(file_id, attr_name, value, setxattr_func):
      value = str(value)
      got = setxattr_func(file_id, attr_name, value, len(value), 0)
      if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, '%s: %r' % (os.strerror(err), file_id))

    def removexattr(filename, attr_name, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __removexattr_low(filename, attr_name, LIBC_CTYPES.lremovexattr)
      else:
        return __removexattr_low(filename, attr_name, LIBC_CTYPES.removexattr)

    def fremovexattr(fd, attr_name):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __removexattr_low(fd, attr_name, LIBC_CTYPES.fremovexattr)

    def __removexattr_low(file_id, attr_name, removexattr_func):
      got = removexattr_func(file_id, attr_name)
      if got < 0:
        err = ctypes.get_errno()
        if err != CTYPES_ENOATTR:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))

    def listxattr(filename, do_not_follow_symlinks=False):
      if do_not_follow_symlinks:
        return __listxattr_low(filename, LIBC_CTYPES.llistxattr)
      else:
        return __listxattr_low(filename, LIBC_CTYPES.listxattr)

    def flistxattr(fd):
      if not isinstance(fd, int):
        fd = fd.fileno()
      return __listxattr_low(fd, LIBC_CTYPES.flistxattr)

    def __listxattr_low(file_id, listxattr_func):
      value = 'x' * 256
      got = listxattr_func(file_id, value, len(value))
      if got < 0:
        err = ctypes.get_errno()
        if err != errno.ERANGE:
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        got = listxattr_func(file_id, None, 0)
        if got < 0:
          err = ctypes.get_errno()
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
        assert got > len(value)
        value = 'x' * got
        # We have a race condition here, someone might have changed the xattr
        # by now.
        got = listxattr_func(file_id, value, got)
        if got < 0:
          err = ctypes.get_errno()
          raise OSError(err, '%s: %r' % (os.strerror(err), file_id))
      if got:
        assert got <= len(value)
        assert value[got - 1] == '\0'
        return value[:got - 1].split('\0')
      else:
        return []

assert IMPL, ('could not find implementation for extended attributes; please '
              'install the xattr Python package (>=0.2.2): '
              '(easy_install xattr) or (sudo apt-get install python-xattr)')

listxattr.__doc__ = """List the extended attributes of a file.

Args:
  filename: Name of the file or directory.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Returns:
  (New) list of str containing the extended attribute names.
Raises:
  OSError: If the file does not exists or the extended attributes cannot be
    read.
"""

flistxattr.__doc__ = """List the extended attributes of an open file.

Args:
  fd: File descriptor (nonnegative integer) or file object with .fileno().
Returns:
  (New) list of str containing the extended attribute names.
Raises:
  OSError: If the file does not exists or the extended attributes cannot be
    read.
"""

getxattr.__doc__ = """Get an extended attribute of a file.

Args:
  filename: Name of the file or directory.
  xattr_name: Name of the extended attribute.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Returns:
  str containing the value of the extended attribute, or None if the file
  exists, but doesn't have the specified extended attribute.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

fgetxattr.__doc__ = """Get an extended attribute of an open file.

Args:
  fd: File descriptor (nonnegative integer) or file object with .fileno().
  xattr_name: Name of the extended attribute.
Returns:
  str containing the value of the extended attribute, or None if the file
  exists, but doesn't have the specified extended attribute.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

setxattr.__doc__ = """Set an extended attribute of a file.

Args:
  filename: Name of the file or directory.
  xattr_name: Name of the extended attribute.
  value: New str value of the new extended attribute.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

fsetxattr.__doc__ = """Set an extended attribute of an open file.

Args:
  fd: File descriptor (nonnegative integer) or file object with .fileno().
  xattr_name: Name of the extended attribute.
  value: New str value of the new extended attribute.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

removexattr.__doc__ = """Remove an extended attribute from a file.

Args:
  filename: Name of the file or directory.
  xattr_name: Name of the extended attribute.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

fremovexattr.__doc__ = """Remove an extended attribute from an open file.

Args:
  fd: File descriptor (nonnegative integer) or file object with .fileno().
  xattr_name: Name of the extended attribute.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
"""

if __name__ == '__main__':
  print IMPL

  filename = 'f\x9f.'
  attr_name = 'user.f\xb4.'
  try:
    os.unlink(filename)
  except OSError, e:
    pass
  try:
    setxattr(filename, 'user.foo', 'Initial.')
  except OSError, e:
    print str(e)
  f = open(filename, 'w')
  setxattr(filename, 'user.foo', 'The quick brown fox jumps ', 1)
  print repr(fgetxattr(f, 'user.foo'))
  fsetxattr(f.fileno(), 'user.foo', 'over the lazy dog.')
  print repr(getxattr(filename, 'user.foo'))
  print fremovexattr(f, 'user.foo')
  print removexattr(filename, 'user.foo', 1)
  print removexattr(filename, 'user.foo', 1)
  print repr(getxattr(filename, 'user.foo', 1))
  f.close()

  print repr(listxattr('im/014.jpg'))
  print repr(listxattr('im/0'))
  print repr(listxattr('im/0', 1))
  try:
    data = getxattr('im/0', 'user.answer', 1)
  except OSError, e:
    data = str(e)
  print repr(data)
  print repr(flistxattr(open('im/0')))
  print repr(getxattr('im/024.jpg', 'user.bad'))
  print repr(getxattr('im/024.jpg', 'user.mmfs.tags'))
  f = open('im/024.jpg')
  print repr(fgetxattr(f.fileno(), 'user.mmfs.tags'))
  try:
    print listxattr('/proc/missing')
  except OSError, e:
    print str(e)
