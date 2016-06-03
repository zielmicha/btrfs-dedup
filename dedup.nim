import extentmap, posix, securehash, os, tables, hashes, extentsame, strutils, options

var fileNames: seq[string]
var O_NOFOLLOW {.importc, header: "<sys/types.h>".}: cint

type
  Extent = tuple
    fileId: int
    offset: uint64
    length: uint64
    physicalId: uint64

proc getHash(fd: FileHandle, offset: uint64, length: uint64): tuple[hash: SecureHash, length: uint64] =
  discard lseek(fd.cint, offset.cint, 0)
  var buffer {.global.} = newString(1024 * 1024)
  buffer.setLen(length)
  let readSize = read(fd, addr buffer[0], length.int)
  if readSize < 0:
    raiseOSError(osLastError())
  if readSize != length.int:
    buffer.setLen(readSize)
  return (secureHash(buffer), readSize.uint64)

proc hash(s: SecureHash): int =
  return array[20, uint8](s).hash

proc hash(s: uint64): int =
  return cast[int](s)

proc firstValue(t: auto): auto =
  for val in t.values:
    return val
  doAssert(false)

proc openFd(path: string, write=false): FileHandle =
  let fd = posix.open(path, (if write: O_RDWR else: O_RDONLY) or O_NOFOLLOW).FileHandle
  if fd < 0:
    raiseOSError(osLastError())
  return fd

proc dedup() =
  var byHash = initTable[SecureHash, seq[Extent]]()

  var segI: uint64 = 0
  for fileNum in 0..<fileNames.len:
    echo "processing ", fileNames[fileNum]
    var fd: FileHandle
    var extents: seq[FiemapExtent]
    try:
      fd = openFd(fileNames[fileNum])
      extents = getExtents(fileNames[fileNum])
    except OSError:
      echo fileNames[fileNum], ": ", getCurrentException().msg
      continue

    var size: uint64 = 0
    for extent in extents:
      size += extent.length

    let blockBits = 17
    let blockSize = 1.uint64 shl blockBits.uint64

    for i in 0..<(size shr blockBits.uint64):
      let offset = i * blockSize
      segI += 1
      let (hash, length) = getHash(fd, offset, blockSize)
      byHash.mgetOrPut(hash, @[]).add((fileNum, offset, length, segI).Extent)

    discard close(fd)

  for list in byHash.values:
    var uniqueExtents = initTable[uint64, tuple[fileId: int, offset: uint64]]()
    var length: uint64 = 0
    for extent in list:
      let ident: uint64 = extent.physicalId
      length = extent.length
      uniqueExtents[ident] = (extent.fileId, extent.offset)

    let first = uniqueExtents.firstValue
    let firstFd = openFd(fileNames[first.fileId], write=true)
    defer: discard close(firstFd)
    for item in uniqueExtents.values:
      if first == item:
        continue

      echo "dedup ", first, " with ", item
      let itemFd = openFd(fileNames[item.fileId], write=true)
      defer: discard close(itemFd)
      extentsame.extentSame((firstFd, first.offset).ExtentInfo, (itemFd, item.offset).ExtentInfo, length)

when isMainModule:
  fileNames = @[]
  for fn in stdin.readAll().split("\L"):
    if fn.len == 0:
      break
    fileNames.add fn
  dedup()
