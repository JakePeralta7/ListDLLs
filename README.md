# ListDLLs
![GitHub Created At](https://img.shields.io/github/created-at/JakePeralta7/ListDLLs?color=blue)
![GitHub contributors](https://img.shields.io/github/contributors/JakePeralta7/ListDLLs)
![GitHub Release](https://img.shields.io/github/v/release/JakePeralta7/ListDLLs)
[![GitHub Issues](https://img.shields.io/github/issues/JakePeralta7/ListDLLs)](https://github.com/JakePeralta7/ListDLLs/issues)
 
## Build
```
windres version.rc -o version.o
gcc .\src\list_dlls.c version.o -o list_dlls_x64.exe -s -m64
```

## Usage
```
list_dlls_x64.exe <output_csv_file>
```
