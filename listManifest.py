#/usr/bin/env python
# Fri Dec 21 20:37:53 CET 2012  A. Ramos <aramosf @ gmail.com >
# 
# Parse Manifest.mbdb binary database file from iTunes Backup and print CSV
# permissions|inode|uid|guid|size|class|mtime|atime|ctime|
# fileid|domain|application|filename|properties1|properties2|properties3
#
# mix code from:
# http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup
# http://www.securitylearn.net/tag/manifest-mbdb-format/

import sys
import hashlib
import re
from struct import unpack
from time import localtime, strftime, gmtime


if len(sys.argv)!=2:
	print "\nUsage: python listManifest.py [Full path to Manifest.mbdb file]"
	print "Example: python listManifest.py /tmp/Manifest.mbdb"
	sys.exit(0)
manifest=sys.argv[1]

try:
	mbdb =  file(manifest, 'rb')
except IOError as e:
	print 'File Not Found :'+ manifest
	sys.exit(0)

mbdx = {}

def getint(data, offset, intsize):
    """Retrieve an integer (big-endian) and new offset from the current offset"""
    value = 0
    while intsize > 0:
        value = (value<<8) + ord(data[offset])
        offset = offset + 1
        intsize = intsize - 1
    return value, offset

def getstring(data, offset):
    """Retrieve a string and new offset from the current offset into the data"""
    if data[offset] == chr(0xFF) and data[offset+1] == chr(0xFF):
        return '', offset+2 # Blank string
    length, offset = getint(data, offset, 2) # 2-byte length
    value = data[offset:offset+length]
    return value, (offset + length)

def process_mbdb_file(filename):
    mbdb = {} # Map offset of info in this file => file info
    data = open(filename).read()
    if data[0:4] != "mbdb": raise Exception("This does not look like an MBDB file")
    offset = 4
    offset = offset + 2 # value x05 x00, not sure what this is
    while offset < len(data):
        fileinfo = {}
        fileinfo['start_offset'] = offset
        fileinfo['domain'], offset = getstring(data, offset)
        fileinfo['filename'], offset = getstring(data, offset)
        fileinfo['linktarget'], offset = getstring(data, offset)
        fileinfo['datahash'], offset = getstring(data, offset)
        fileinfo['enckey'], offset = getstring(data, offset)
        fileinfo['mode'], offset = getint(data, offset, 2)
        fileinfo['inode'], offset = getint(data, offset, 8)
        fileinfo['userid'], offset = getint(data, offset, 4)
        fileinfo['groupid'], offset = getint(data, offset, 4)
        fileinfo['mtime'], offset = getint(data, offset, 4)
        fileinfo['atime'], offset = getint(data, offset, 4)
        fileinfo['ctime'], offset = getint(data, offset, 4)
        fileinfo['filelen'], offset = getint(data, offset, 8)
        fileinfo['flag'], offset = getint(data, offset, 1)
        fileinfo['numprops'], offset = getint(data, offset, 1)
        fileinfo['properties'] = {}
        for ii in range(fileinfo['numprops']):
            propname, offset = getstring(data, offset)
            propval, offset = getstring(data, offset)
            fileinfo['properties'][propname] = propval
        mbdb[fileinfo['start_offset']] = fileinfo
        fullpath = fileinfo['domain'] + '-' + fileinfo['filename']
        id = hashlib.sha1(fullpath)
        mbdx[fileinfo['start_offset']] = id.hexdigest()
    return mbdb

def modestr(val):
    def mode(val):
        if (val & 0x4): r = 'r'
        else: r = '-'
        if (val & 0x2): w = 'w'
        else: w = '-'
        if (val & 0x1): x = 'x'
        else: x = '-'
        return r+w+x
    return mode(val>>6) + mode((val>>3)) + mode(val)

def dom(val):
   matchobj = re.match( r'(AppDomain)', val, re.M|re.I)
   if matchobj:
	return matchobj.group()
   else:
        return val

def app(appstr):
   matchobjapp = re.match( r'(AppDomain)-(.*)', appstr, re.M|re.I)
   if matchobjapp:
	return matchobjapp.group(2)
   else:
        return ""

def classstr(val):
   if val == 1: string = "NSProtectionComplete"
   elif val == 2: string = "NSFileProtectionCompleteUnlessOpen"
   elif val == 3: string = "NSFileProtectionCompleteUntilFirstUserAuthentication"
   elif val == 4: string = "NSFileProtectionNone"
   elif val == 5: string = "NSFileProtectionRecovery"
   else: string = "Unknown: "+str(val)
   return string

def fileinfo_str(f, verbose=True):
    if not verbose: return "(%s)%s::%s" % (f['fileID'], dom(f['domain']), app(f['domain']), f['filename'])
    if (f['mode'] & 0xE000) == 0xA000: type = 'l' # symlink
    elif (f['mode'] & 0xE000) == 0x8000: type = '-' # file
    elif (f['mode'] & 0xE000) == 0x4000: type = 'd' # dir
    else:
        print >> sys.stderr, "Unknown file type %04x for %s" % (f['mode'], fileinfo_str(f, False))
        type = '?' # unknown
    info = ("%s%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" %
            (type, modestr(f['mode']&0x0FFF), f['inode'], f['userid'], f['groupid'], f['filelen'], classstr(f['flag']),
             convert_times(f['mtime']), convert_times(f['atime']), convert_times(f['ctime']), f['fileID'], 
	     dom(f['domain']), app(f['domain']), f['filename']))
    if type == 'l': info = info + ' -> ' + f['linktarget'] # symlink destination
    for name, value in f['properties'].items(): # extra properties
        info = info + '|' + name + '=' + repr(value)
    return info

def convert_times(datecode):
    datecode = int(datecode)
    time = strftime('%Y-%m-%d %H:%M:%S (%Z)', localtime(datecode))
    return time

verbose = True
if __name__ == '__main__':
    mbdb = process_mbdb_file(manifest)
    print "permissions|inode|uid|guid|size|class|mtime|atime|ctime|fileid|domain|application|filename|proprties1|prop2|prop3"
    for offset, fileinfo in mbdb.items():
        if offset in mbdx:
            fileinfo['fileID'] = mbdx[offset]
        else:
            fileinfo['fileID'] = "<nofileID>"
            print >> sys.stderr, "No fileID found for %s" % fileinfo_str(fileinfo)
        print fileinfo_str(fileinfo, verbose)

