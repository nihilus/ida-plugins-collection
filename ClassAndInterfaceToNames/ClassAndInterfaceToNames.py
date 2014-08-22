"""
ClassAndInterfaceToNames.py - 14/07/2007
This small IDAPython script scans an idb file for class and interfaces UUIDs
and creates the matching structure and its name. Unfortunately IDA doesn't
do this automatically, thus this little helper. It personally helped me alot,
while reversing several malwares using the COM interface, e.g. for browser
or outlook manipulation, BITS file transfer or dumping the protected storage.
The script was tested with IDAPython v0.9.0 and Python 2.4
Make sure to copy interfaces.txt + classes.txt + ClassAndInterfaceToNames.py
to IDADIR, e.g. C:\Program Files\IDA

The classes and interfaces database is still not complete at the moment!
I'll try add more UUIDs when there's some free time.
Third party support with these infos is highly appreciated! ;)
"""

__author__ = 'Frank Boldewin / www.reconstructer.org'
__version__ = '0.3'
__license__ = 'GPL'

import string, os, glob, binascii
from idaapi import *

def ASCII2Hex(value):
  return ' '.join(map(binascii.hexlify,value))

def PreparateUUIDS(CurrentUUID):

  UUID_SPLIT = CurrentUUID.replace('-',' ').split(' ')

  DATA1=''.join(map(lambda (i): chr(0xff & (int(UUID_SPLIT[0],16) >> 8*i)), range(4)))
  DATA2=''.join(map(lambda (i): chr(0xff & (int(UUID_SPLIT[1],16) >> 8*i)), range(2)))
  DATA3=''.join(map(lambda (i): chr(0xff & (int(UUID_SPLIT[2],16) >> 8*i)), range(2)))

  DATA4a = []
  DATA4b = []

  i=0
  
  while i < len(UUID_SPLIT[3]):
    DATA4a.append(UUID_SPLIT[3][i:i+2])
    i = i + 2

  i=0

  while i < len(UUID_SPLIT[4]):
    DATA4b.append(UUID_SPLIT[4][i:i+2])
    i = i + 2

  DATA4=DATA4a+DATA4b

  PREPAREDDATA=ASCII2Hex(DATA1) + " " + ASCII2Hex(DATA2) + " " + ASCII2Hex(DATA3) + " " + ' '.join(DATA4) + "," + UUID_SPLIT[5]
  
  return PREPAREDDATA
    
def main():
  FILEUUID_CLASSES    = idadir("") + '\\classes.txt'
  FILEUUID_INTERFACES = idadir("") + '\\interfaces.txt'

  UUIDARRAY = []
  UUIDARRAYIndexValue = 0

  print "Reading " + FILEUUID_INTERFACES + " into memory..."

  file = open(FILEUUID_INTERFACES,"r")
  try:
    for line in file:
       if len(line.strip()) !=0:
         UUIDENTRY = {"INTERFACE":""}
         UUIDENTRY["INTERFACE"] = line.strip()
         UUIDARRAY.append(UUIDENTRY)
  finally:
     file.close()

  print "Scanning for interface UUIDs..."

  for UUIDARRAYIndexValue in UUIDARRAY:
    CurrentUUID = UUIDARRAYIndexValue["INTERFACE"]
    PREPAREDDATA=PreparateUUIDS(CurrentUUID)

    i = PREPAREDDATA.find(",")
    IDAFINDSTRING = PREPAREDDATA[0:i]
    UUIDTYPE = "IID_" + PREPAREDDATA[i+1:]

    ea = 0
    i  = 0
    
    while (1):
      ea = FindBinary(ea, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW, IDAFINDSTRING)
      if ea == BADADDR:
        break
      else:
        for i in range(0,16):
          MakeUnkn(ea+i,0)
        id=GetStrucIdByName("IID")
        if id == 0xffffffff:
          id = AddStrucEx(0xffffffff,"IID",0)
          id = GetStrucIdByName("IID");
          AddStrucMember(id,"Data1",0x0,0x20000000, -1,4);
          AddStrucMember(id,"Data2",0x4,0x10000000, -1,2);
          AddStrucMember(id,"Data3",0x6,0x10000000, -1,2);
          AddStrucMember(id,"Data4",0x8,0x00000000, -1,8);
        doStruct(ea, GetStrucSize(id), id)
        rc=MakeNameEx(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
        if rc==0:
          for i in range(2,1000):
            UUIDTYPE = UUIDTYPE + "__" + str(i)
            rc=MakeNameEx(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
            if rc==1:
              print "Created Interface " + UUIDTYPE + " at address " + hex(ea)
              break
        else:
          print "Created Interface " + UUIDTYPE + " at address " + hex(ea)

  UUIDARRAY = []
  UUIDARRAYIndexValue = 0

  print "Reading " + FILEUUID_CLASSES + " into memory..."

  file = open(FILEUUID_CLASSES,"r")
  try:
    for line in file:
       if len(line.strip()) !=0:      
         UUIDENTRY = {"CLASS":""}
         UUIDENTRY["CLASS"] = line.strip()
         UUIDARRAY.append(UUIDENTRY)
  finally:
     file.close()

  print "Scanning for class UUIDs..."

  for UUIDARRAYIndexValue in UUIDARRAY:
    CurrentUUID = UUIDARRAYIndexValue["CLASS"]
    PREPAREDDATA=PreparateUUIDS(CurrentUUID)

    i = PREPAREDDATA.find(",")
    IDAFINDSTRING = PREPAREDDATA[0:i]
    UUIDTYPE = "CLSID_" + PREPAREDDATA[i+1:]

    ea = 0
    i  = 0
    
    while (1):
      ea = FindBinary(ea, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW, IDAFINDSTRING)
      if ea == BADADDR:
        break
      else:
        for i in range(0,16):
          MakeUnkn(ea+i,0)
        id=GetStrucIdByName("CLSID")
        if id == 0xffffffff:
          id = AddStrucEx(0xffffffff,"CLSID",0)
          id = GetStrucIdByName("CLSID");
          AddStrucMember(id,"Data1",0x0,0x20000000, -1,4);
          AddStrucMember(id,"Data2",0x4,0x10000000, -1,2);
          AddStrucMember(id,"Data3",0x6,0x10000000, -1,2);
          AddStrucMember(id,"Data4",0x8,0x00000000, -1,8);
        doStruct(ea, GetStrucSize(id), id)
        rc=MakeNameEx(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
        if rc==0:
          for i in range(2,1000):
            UUIDTYPE = UUIDTYPE + "__" + str(i)
            rc=MakeNameEx(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
            if rc==1:
              print "Created ClassID " + UUIDTYPE + " at address " + hex(ea)
              break
        else:
          print "Created ClassID " + UUIDTYPE + " at address " + hex(ea)

  print "Everything finished!"

if __name__ == "__main__":
  main()
