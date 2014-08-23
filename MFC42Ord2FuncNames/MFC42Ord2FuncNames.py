"""
MFC42Ord2FuncNames.py - 06/06/2007
This small IDAPython script converts MFC42 functions into
its realnames. Normally IDA Pro should do this automatically,
but in some cases the IDA auto-analysis fails (versions < 5.1)
The script was tested with IDAPython v0.8.0/v0.9.0
Make sure to copy MFC42.DEF + MFC42Ord2FuncNames.py to IDADIR,
e.g. C:\Program Files\IDA
"""

__author__ = 'Frank Boldewin / www.reconstructer.org'
__version__ = '0.2'
__license__ = 'GPL'

import string, os, glob
from idaapi import *

def main():
    filename = idadir("") + '\\mfc42.def'
  
    MFC42IDATableIndexValue = 0
    MFC42IDATable = []
    
    for seg_ea in Segments():
      for function_ea in Functions(seg_ea, SegEnd(seg_ea)):
        func = GetFunctionName(function_ea)
        if func.find("MFC42_") == 0:
          func = func[6:]
          MFC42IDATableMembers = {"Ordinal":"","Addr":""}
          MFC42IDATableMembers["Ordinal"] = func.strip()
          MFC42IDATableMembers["Addr"] = hex(function_ea)
          MFC42IDATable.append(MFC42IDATableMembers)
             
    MFC42FileTable = []
    MFC42FileTableIndexValue = 0

    file = open(filename,"r")
    try:
      for line in file: 
        i = line.find(" ")
        MFC42FileTableMembers = {"FuncName":"","Ordinal":""}
        MFC42FileTableMembers["FuncName"] = line[0:i]
        MFC42FileTableMembers["Ordinal"] = line[i+1:].strip()
        MFC42FileTable.append(MFC42FileTableMembers)
    finally:
      file.close()
    
    print "scanning for unrecognized MFC42 Ordinals..."
    
    for MFC42IDATableIndexValue in MFC42IDATable:
      for MFC42FileTableIndexValue in MFC42FileTable:
        if MFC42IDATableIndexValue["Ordinal"] == MFC42FileTableIndexValue["Ordinal"]:
          MakeNameEx(Hex2Dec(MFC42IDATableIndexValue["Addr"]),MFC42FileTableIndexValue["FuncName"],SN_AUTO | SN_NOCHECK)
          print "MFC42 Ordinal " + MFC42IDATableIndexValue["Ordinal"] + " was converted into function name " + MFC42FileTableIndexValue["FuncName"] + " at address " + MFC42IDATableIndexValue["Addr"]
          
    print "scanning finished!"
    
def Hex2Dec(k):
	val = int(k,16)
	return val

if __name__ == "__main__":
  main()
