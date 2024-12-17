# ListDLLs
 
## Build
```
windres .\version.rc -o version.o
gcc .\src\list_dlls.c .\version.o -o list_dlls_x64.exe -s -m64
```

## Usage
```
list_dlls_x64.exe <output_csv_file>
```