# scans PID for utf-8 string with option to stop on first occurence
# adjusted code taken from Awesometech here https://python-forum.io/thread-5517.html

import ctypes
from ctypes.wintypes import WORD, DWORD, LPVOID, MAX_PATH, HANDLE, HMODULE, LPWSTR
import sys, os
 
 
class SYSTEM_INFO(ctypes.Structure):
 """https://msdn.microsoft.com/en-us/library/ms724958"""
 class _U(ctypes.Union):
  class _S(ctypes.Structure):
   _fields_ = (('wProcessorArchitecture', WORD),
      ('wReserved', WORD))
  _fields_ = (('dwOemId', DWORD), # obsolete
     ('_s', _S))
  _anonymous_ = ('_s',)
 
 
 if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
  DWORD_PTR = ctypes.c_ulonglong
 elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
  DWORD_PTR = ctypes.c_ulong
 
 _fields_ = (('_u', _U),
    ('dwPageSize', DWORD),
    ('lpMinimumApplicationAddress', LPVOID),
    ('lpMaximumApplicationAddress', LPVOID),
    ('dwActiveProcessorMask',   DWORD_PTR),
    ('dwNumberOfProcessors', DWORD),
    ('dwProcessorType',   DWORD),
    ('dwAllocationGranularity', DWORD),
    ('wProcessorLevel', WORD),
    ('wProcessorRevision', WORD))
 _anonymous_ = ('_u',)

 
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
 """https://msdn.microsoft.com/en-us/library/aa366775"""
 PVOID = LPVOID
 SIZE_T = ctypes.c_size_t
 _fields_ = (('BaseAddress', PVOID),
    ('AllocationBase', PVOID),
    ('AllocationProtect', DWORD),
    ('RegionSize', SIZE_T),
    ('State',   DWORD),
    ('Protect', DWORD),
    ('Type', DWORD))
 
 
# Define GetModuleFileNameEx API
_GetModuleFileNameEx = ctypes.windll.psapi.GetModuleFileNameExW
_GetModuleFileNameEx.argtypes = HANDLE, HMODULE, LPWSTR, DWORD
_GetModuleFileNameEx.restype = DWORD 
 

def main(PID = os.getpid(), FIND_STR='ąsdf1234', _exit_on_first_match=True, REPLACE_STR="Afine"):

 findstr= bytearray(FIND_STR.encode('utf-8'))
 replacestr=bytearray(REPLACE_STR.encode('utf-8'))
 
 if len(replacestr) > len(findstr):
     print("Replace string length is bigger than searching string!!!")
     exit(-1)

 print("\nProcess Memory Scanning Tool v0.2 by Michał Majchrowicz AFINE Team\n");
 print(f'\n*** Searching {FIND_STR} in PID {PID} _exit_on_first_match {_exit_on_first_match}\nReplacing with: {REPLACE_STR}\n' )
 
 LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO) ##PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION)  
  
 Kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
 Kernel32.GetSystemInfo.restype = None
 Kernel32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)
 ReadProcessMemory = Kernel32.ReadProcessMemory
  
 sysinfo = SYSTEM_INFO()
 Kernel32.GetSystemInfo(ctypes.byref(sysinfo))
 start_addr=sysinfo.lpMinimumApplicationAddress
 current_address = sysinfo.lpMinimumApplicationAddress
 end_address = sysinfo.lpMaximumApplicationAddress
 
 
 PROCESS_QUERY_INFORMATION = 0x0400
 PROCESS_VM_READ = 0x0010
 PROCESS_VM_WRITE = 0x0020
 MEM_COMMIT = 0x00001000;
 PAGE_READWRITE = 0x04;
  
 procHandle = Kernel32.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE, False, PID) 

 mbi = MEMORY_BASIC_INFORMATION() 
 
 one_char_buffer = ctypes.c_char() #c_double() ##buffer = ctypes.c_uint()
 #buffer = ctypes.c_char()*1100
 step_size=0x1000
 buffer = ctypes.create_string_buffer(step_size+0x100)
 nread = ctypes.c_size_t() #SIZE_T()
 nwritten = ctypes.c_size_t() #SIZE_T()

 address_space_size=0
 lpFilename = ctypes.create_unicode_buffer(MAX_PATH)
  
 current_address = sysinfo.lpMinimumApplicationAddress
 ci=0
 count_occur=0
 while current_address < end_address:
  current_address_ctypes=ctypes.c_void_p(current_address) 
  _k=Kernel32.VirtualQueryEx(procHandle,  current_address_ctypes, ctypes.byref(mbi), ctypes.sizeof(mbi)) # read cur region to mbi
  if _GetModuleFileNameEx(procHandle, mbi.AllocationBase, lpFilename, MAX_PATH) > 0:
   module_path, module_name = os.path.split(lpFilename.value)
   if module_name.lower().endswith(".dll") or module_name.lower().endswith(".drv"):
       print(f"Ignoring DLL module: {module_name}...")
       print(f"\tProgress done 0x{current_address-start_addr:08x} {round(100*(current_address-start_addr)/(end_address-start_addr))}%, left 0x{end_address-current_address:08x}, this iter did 0x{mbi.RegionSize:08x}") 
       current_address += mbi.RegionSize
       continue
   else:
       print(f"Module: {module_name}")
  if mbi.Protect == PAGE_READWRITE and mbi.State == MEM_COMMIT : # print('This region can be scanned!',index,end, end-index)
   
   index = current_address
   end = current_address + mbi.RegionSize

   
   #ci=0
   while index < end: # index -> ctypes.c_void_p(index) ?
    rm=ReadProcessMemory(procHandle, ctypes.c_void_p(index), ctypes.byref(buffer),  ctypes.sizeof(buffer), ctypes.byref(nread)) # read cur region bytes to bugger
    #print(f"rm: {rm}, nread: {nread}")
    buffer_bytes_array=bytes(buffer)
    #print(f"buffer: {bytes(buffer)[4]}")
    if rm>0 :
     f_ind=-1
     for bi in range(0,len(buffer_bytes_array)-0x100):
         for ci in range(0,len(findstr)):
             _x=findstr[ci].to_bytes(1, 'little')
             _x_bi=buffer_bytes_array[bi+ci]
             #print(f"{_x[0]} {_x_bi}")
             if buffer_bytes_array[bi+ci]!=_x[0]:
                 break
             #if ci > 2:
             #   print(f"Found: {ci}")
             if ci==0: f_ind=index+bi
             if ci==len(findstr)-1:
              count_occur+=1
              print(f'MATCHED [{count_occur}] STRING between indexes 0x{f_ind:08x} and 0x{(f_ind+ci):08x}') 
              for cnum in range(0, len(replacestr)):
                one_char_buffer.value=replacestr[cnum].to_bytes(1,'little')
                wrm=Kernel32.WriteProcessMemory(procHandle, ctypes.c_void_p(f_ind+cnum), ctypes.byref(one_char_buffer),  ctypes.sizeof(one_char_buffer), ctypes.byref(nwritten)) # read cur region bytes to bugger
                #print(f"{wrm}, {nwritten}")
                if _exit_on_first_match:
                  print('\texiting on _exit_on_first_match',_exit_on_first_match)
                  return
        
       #else: ci, f_ind, vi = 0, -1, [] 
     #else: ci, f_ind, vi=0, -1, [] 
    #else: ci, f_ind, vi = 0, -1, [] 
     
    #index += ctypes.sizeof(buffer) 
    #print(nread.value)
    if nread.value < step_size and nread.value > 0:
        index += nread.value
    else:
        index += step_size
     
  
  
  print(f"\tProgress done 0x{current_address-start_addr:08x} {round(100*(current_address-start_addr)/(end_address-start_addr))}%, left 0x{end_address-current_address:08x}, this iter did 0x{mbi.RegionSize:08x}") 
  
  current_address += mbi.RegionSize




# arg1: pid, arg2=search string unicode , arg3=True/False if exit on first match 
if __name__ == '__main__':
 
 if len(sys.argv)==3:
  main(int(sys.argv[1]),sys.argv[2])
 elif len(sys.argv)==4:
  main(int(sys.argv[1]), sys.argv[2], sys.argv[3].lower()=='true')
 elif len(sys.argv)==5:
  main(int(sys.argv[1]), sys.argv[2], sys.argv[3].lower()=='true', sys.argv[4])
 else:
  print('\n=== To customize provide arguments: PID UTF8_STRING_TO_SEARCH EXIT_ON_FIRST_MATCH=True/False')
  print('=== Arguments example: 1234 sometext False\n')
  main()
  
 print('\n*** Finished scanning memory\n')
