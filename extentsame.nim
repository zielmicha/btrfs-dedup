import posix, os, strutils

const header = splitPath(currentSourcePath()).head / "btrfs-ioctl.h"
var BTRFS_IOC_FILE_EXTENT_SAME {.importc, header: header.}: uint

type
  btrfs_ioctl_same_extent_info = object
    fd: int64
    offset: uint64
    bytesDeduped: uint64
    status: int32
    reserved: uint32

  btrfs_ioctl_same_args = object
    logicalOffset: uint64
    length: uint64
    destCount: uint16
    reserved1: uint16
    reserved2: uint32
    info: btrfs_ioctl_same_extent_info

type ExtentInfo* = tuple[fd: FileHandle, offset: uint64]

proc extentSame*(src: ExtentInfo, dst: ExtentInfo, length: uint64) =
  let args = create(btrfs_ioctl_same_args)
  defer: dealloc(args)
  args.logicalOffset = src.offset
  args.length = length
  args.destCount = 1
  args.info.fd = dst.fd
  args.info.offset = dst.offset
  let ret = ioctl(src.fd, BTRFS_IOC_FILE_EXTENT_SAME, args)

  if ret < 0:
    raiseOSError(osLastError())

  if args.info.status != 0:
    raise newException(OSError, "extent-same returned $1" % [$args.info.status])
