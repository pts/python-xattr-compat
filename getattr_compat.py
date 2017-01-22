#! /usr/bin/python
# by pts@fazekas.hu at Sun Jan 22 09:48:10 CET 2017
# based on xattr_compat.py by pts@fazekas.hu at Sat Apr  9 14:20:09 CEST 2011
#
# Tested on Linux >=2.6 only.
#
# TODO(pts): Test Mac OS X. xattr should work. What about ctyles?

import errno
import os
import sys

XATTR_KEYS = ('getxattr', 'fgetxattr', 'listxattr', 'flistxattr')

XATTR_DOCS = {
    'getxattr': """Get an extended attribute of a file.

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
""",
    'listxattr': """List the extended attributes of a file.

Args:
  filename: Name of the file or directory.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default.
Returns:
  (New) list of str containing the extended attribute names.
Raises:
  OSError: If the file does not exists or the extended attributes cannot be
    read.
""",
}


def _xattr_doc(name, function):
  function.__doc__ = XATTR_DOCS[name]
  return name, function


def xattr_impl_xattr():
  import errno

  # sudo apt-get install python-xattr
  # pip install xattr
  #
  # Please note that there is python-pyxattr, it's different.
  import xattr

  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', -1))
  del errno  # Save memory.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    try:
      # This does 2 lgetattxattr(2) syscalls,the first to determine size.
      return xattr._xattr.getxattr(
          filename, attr_name, 0, 0, do_not_follow_symlinks)
    except IOError, e:
      if e[0] != XATTR_ENOATTR:
        # We convert the IOError raised by the _xattr module to OSError
        # expected from us.
        raise OSError(e[0], e[1])
      return None

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

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_impl_dl():
  import dl  # Only i386, in Python >= 2.4.
  import errno
  import os
  import struct

  LIBC_DL = dl.open(None)
  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', -1))
  XATTR_ERANGE = errno.ERANGE
  del errno  # Save memory.
  assert struct.calcsize('l') == 4  # 8 on amd64.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    getxattr_name = ('getxattr', 'lgetxattr')[bool(do_not_follow_symlinks)]
    # TODO(pts): Do we need to protect errno in multithreaded code?
    errno_loc = LIBC_DL.call('__errno_location')
    err_str = 'X' * 4
    value = 'x' * 256
    got = LIBC_DL.call(getxattr_name, filename, attr_name, value, len(value))
    if got < 0:
      LIBC_DL.call('memcpy', err_str, errno_loc, 4)
      err = struct.unpack('i', err_str)[0]
      if err == XATTR_ENOATTR:
        # The file exists, but doesn't have the specified xattr.
        return None
      elif err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = LIBC_DL.call(getxattr_name, filename, attr_name, None, 0)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = LIBC_DL.call(getxattr_name, filename, attr_name, value, got)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      return value
    assert got <= len(value)
    return value[:got]

  def listxattr(filename, do_not_follow_symlinks=False):
    listxattr_name = ('listxattr', 'llistxattr')[bool(do_not_follow_symlinks)]
    errno_loc = LIBC_DL.call('__errno_location')
    err_str = 'X' * 4
    value = 'x' * 256
    got = LIBC_DL.call(listxattr_name, filename, value, len(value))
    if got < 0:
      LIBC_DL.call('memcpy', err_str, errno_loc, 4)
      err = struct.unpack('i', err_str)[0]
      if err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = LIBC_DL.call(listxattr_name, filename, None, 0)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = LIBC_DL.call(listxattr_name, filename, value, got)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
    if got:
      assert got <= len(value)
      assert value[got - 1] == '\0'
      return value[:got - 1].split('\0')
    else:
      return []

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_impl_ctypes():
  import ctypes  # Python >= 2.6. Tested with both i386 and amd64.
  import errno
  import os

  LIBC_CTYPES = ctypes.CDLL(None, use_errno=True)  # Also: 'libc.so.6'.
  functions = dict((k, getattr(LIBC_CTYPES, k)) for k in (
      'lgetxattr', 'getxattr', 'llistxattr', 'listxattr'))
  LIBC_CTYPES = None  # Save memory.
  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', -1))
  XATTR_ERANGE = errno.ERANGE
  del errno  # Save memory.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    getxattr_function = functions[
        ('getxattr', 'lgetxattr')[bool(do_not_follow_symlinks)]]
    value = 'x' * 256
    got = getxattr_function(filename, attr_name, value, len(value))
    if got < 0:
      err = ctypes.get_errno()
      if err == XATTR_ENOATTR:
        # The file exists, but doesn't have the specified xattr.
        return None
      elif err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = getxattr_function(filename, attr_name, None, 0)
      if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = getxattr_function(filename, attr_name, value, got)
      if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      return value
    assert got <= len(value)
    return value[:got]

  def listxattr(filename, do_not_follow_symlinks=False):
    listxattr_function = functions[
        ('listxattr', 'llistxattr')[bool(do_not_follow_symlinks)]]
    value = 'x' * 256
    got = listxattr_function(filename, value, len(value))
    if got < 0:
      err = ctypes.get_errno()
      if err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = listxattr_function(filename, None, 0)
      if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = listxattr_function(filename, value, got)
      if got < 0:
        err = ctypes.get_errno()
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
    if got:
      assert got <= len(value)
      assert value[got - 1] == '\0'
      return value[:got - 1].split('\0')
    else:
      return []

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_detect():
  try:
    import ctypes
    import errno
    try:
      LIBC_CTYPES = ctypes.CDLL(None, use_errno=True)  # Also: 'libc.so.6'.
    except OSError:
      LIBC_CTYPES = None
    if (LIBC_CTYPES and getattr(LIBC_CTYPES, 'lgetxattr', None) and
        getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))):
      return xattr_impl_ctypes
  except ImportError:
    pass

  try:
    import struct
    import dl
    import errno
    try:
      LIBC_DL = dl.open(None)  # Also: dl.open('libc.so.6')
    except dl.error:
      LIBC_DL = None
    if (LIBC_DL and LIBC_DL.sym('memcpy') and LIBC_DL.sym('__errno_location')
        and LIBC_DL.sym('lgetxattr') and
        getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))):
     return xattr_impl_dl
  except ImportError:
    pass

  # We try this last, because it does 2 syscalls by default.
  try:
    import xattr
    # Earlier versions are buggy.
    if getattr(xattr, '__version__', '') >= '0.2.2':
      return xattr_impl_xattr
  except ImportError:
    pass

  raise NotImplementedError(
      'xattr implementation not found. Please install python-xattr or ctypes.')


impl = xattr_detect()()
#impl = xattr_impl_ctypes()
print impl['getxattr']('getattr.py', 'user.mmfs.tags', True)
print impl['getxattr']('hi.txt', 'user.mmfs.tags', True)
print impl['listxattr']('hi.txt')
#print impl['listxattr']('/dev/null/missing')
