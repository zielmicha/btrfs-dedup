import extentmap, posix, securehash, os, tables, hashes, extentsame

var fileNames: seq[string]

type
  Extent = tuple
    fileId: int
    offset: uint64
    length: uint64
    physicalId: uint64

proc getHash(fd: FileHandle, offset: uint64, length: uint64): SecureHash =
  discard lseek(fd.cint, offset.cint, 0)
  var buffer = newString(length)
  let readSize = read(fd, addr buffer[0], length.int)
  if readSize != length.int:
    raiseOSError(osLastError())
  return secureHash(buffer)

proc hash(s: SecureHash): int =
  return array[20, uint8](s).hash

proc hash(s: uint64): int =
  return cast[int](s)

proc firstValue(t: auto): auto =
  for val in t.values:
    return val
  doAssert(false)

proc openFd(path: string, write=false): FileHandle =
  let fd = posix.open(path, if write: O_RDWR else: O_RDONLY).FileHandle
  if fd < 0:
    raiseOSError(osLastError())
  return fd

proc dedup() =
  var byHash = initTable[SecureHash, seq[Extent]]()

  for fileNum in 0..<fileNames.len:
    let fd = openFd(fileNames[fileNum])

    for extent in getExtents(fileNames[fileNum]):
      let hash = getHash(fd, extent.logical, extent.length)
      byHash.mgetOrPut(hash, @[]).add((fileNum, extent.logical, extent.length, extent.physical))

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
  fileNames = @["/data/dedup/rand", "/data/dedup/zero"]
  dedup()
