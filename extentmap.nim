import posix, os

const ExtentCount = 4096

var FS_IOC_FIEMAP {.importc, header: "<linux/fs.h>".}: uint
{.emit: "#include <linux/fiemap.h>".}

type
  FiemapExtent* = object
    logical*: uint64
    physical*: uint64
    length*: uint64
    reserved0*: uint64
    reserved1*: uint64
    flags*: uint32
    reserved2*: uint32
    reserved3*: uint64

  Fiemap = object
    start: uint64
    length: uint64
    flags: uint32
    mappedExtents: uint32
    extentCount: uint32
    reserved: uint32
    extents: array[ExtentCount, FiemapExtent]

proc getExtents*(filename: string): seq[FiemapExtent] =
  let fd = posix.open(filename, O_RDONLY).FileHandle
  if fd < 0:
    raiseOSError(osLastError())
  var fiemap: ptr Fiemap = create(Fiemap)
  fiemap.start = 0
  fiemap.length = not uint64(0)
  fiemap.extentCount = ExtentCount
  defer:
    discard close(fd)
    dealloc(fiemap)
  let err = ioctl(fd, FS_IOC_FIEMAP, cast[culong](fiemap))
  if err < 0:
    raiseOSError(osLastError())
  return @(fiemap.extents[0..<fiemap.mappedExtents.int])
