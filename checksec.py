#!/usr/bin/env python
"""
Copyright (C) 2016 Kukhyun Lee <kukhyun at gmail.com>
"""

import os.path
import sys
import pefile

class CheckSec:
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_SEH       = 0x0400
    IMAGE_DLLCHARACTERISTICS_GUARD_CF     = 0x4000

    def __init__(self, pe):
        self.pe = pe

    def run(self):
        result = {}
        for type in ["aslr", "dep", "seh", "cfg"]:
            result[type] = self.check(type)
        return result
            
    def check(self, type):
        if (type == "aslr"):
            return (self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0
        elif (type == "dep"):
            return (self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0
        elif (type == "seh"):
            return (self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0 
        elif (type == "cfg"):
            return (self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0
        else:
            return False

def header():
    f = '{:<80}{:<8}{:<8}{:<8}{:<8}'.format('files', 'ASLR', 'DEP', 'SEH', 'CFG')
    print f
    print '-----------------------------------------------------------------------------------------------------'
        
def file(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        cs = CheckSec(pe)
        result = cs.run()
        f = '{:<80}{:<8}{:<8}{:<8}{:<8}'.format(file_path, str(result["aslr"]), str(result["dep"]),
                                                str(result["seh"]), str(result["cfg"]))
    except pefile.PEFormatError:
        f = '{:<80}      Not a PE file'.format(file_path)
        
    return f

def directory(file_path):
    for file in os.listdir(file_path):
        fullname = os.path.join(file_path, file)
        checkfile(fullname)

def checkfile(file_path):
    if os.path.isfile(file_path):
        form = file(file_path)
        print form
    elif os.path.isdir(file_path):
        directory(file_path)
    else:
        print "'%s' not found!" % file_path
        sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print 'Usage: %s <file_path>' % sys.argv[0]
        sys.exit()

    file_path = sys.argv[1]
    header()
    try:
        checkfile(file_path)
    except pefile.PEFormatError:
        print "Not a PE file!"
        #sys.exit(0)


if __name__ == '__main__':
    main()
