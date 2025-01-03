/*
 * Windows Process Module Scanner
 * This program scans all running processes, enumerates their loaded modules,
 * calculates SHA256 hashes of module files, and outputs the results to a CSV file.
 */

#include <windows.h>
#include <psapi.h>     // For process/module enumeration functions
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>  // For cryptographic functions
#include <string.h>

// Maximum number of entries to store in the hash cache
#define MAX_HASH_ENTRIES 1024

// Structure to cache file hashes to avoid recalculating for duplicate modules
struct HashCacheEntry {
    char filepath[MAX_PATH];
    char hash[65];  // 64 hex chars + null terminator
};

// Global hash cache
struct HashCacheEntry hash_cache[MAX_HASH_ENTRIES];
int cache_size = 0;

// Searches the hash cache for a previously calculated hash
const char* get_cached_hash(const char* filepath) {
    for (int i = 0; i < cache_size; i++) {
        if (strcmp(hash_cache[i].filepath, filepath) == 0) {
            return hash_cache[i].hash;
        }
    }
    return NULL;
}

// Adds a new hash entry to the cache if space is available
void add_to_hash_cache(const char* filepath, const char* hash) {
    if (cache_size < MAX_HASH_ENTRIES) {
        strncpy(hash_cache[cache_size].filepath, filepath, MAX_PATH - 1);
        strncpy(hash_cache[cache_size].hash, hash, 64);
        hash_cache[cache_size].filepath[MAX_PATH - 1] = '\0';
        hash_cache[cache_size].hash[64] = '\0';
        cache_size++;
    }
}

// Properly escapes and quotes strings for CSV output
void sanitize_csv_field(const char* input, char* output) {
    int in_idx = 0, out_idx = 0;
    output[out_idx++] = '"';
    
    // Double up any quotes in the input and wrap the entire field in quotes
    while (input[in_idx] != '\0') {
        if (input[in_idx] == '"') {
            output[out_idx++] = '"';  // Add an extra quote to escape it
        }
        output[out_idx++] = input[in_idx++];
    }
    
    output[out_idx++] = '"';
    output[out_idx] = '\0';
}

// Calculates SHA256 hash of a file
char* calculate_sha256(const char* filename) {
    // Check cache first
    const char* cached_hash = get_cached_hash(filename);
    if (cached_hash) {
        return (char*)cached_hash;
    }

    // Open file for reading
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                             OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    HCRYPTPROV hCryptProv = 0;
    HCRYPTHASH hHash = 0;
    static char hash_string[65];  // Store hex representation of hash

    // Initialize cryptographic provider
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return NULL;
    }

    // Create hash object
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hFile);
        return NULL;
    }

    // Read file in chunks and update hash
    BYTE buffer[8192];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }

    // Get the resulting hash value
    DWORD hashLen = 32;  // SHA256 is 32 bytes
    BYTE hash[32];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hFile);
        return NULL;
    }

    // Convert hash bytes to hexadecimal string
    for (int i = 0; i < hashLen; i++) {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }

    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    CloseHandle(hFile);

    // Cache the result
    add_to_hash_cache(filename, hash_string);

    return hash_string;
}

// Scans all modules loaded in a specific process
int scan_process_modules(DWORD process_id, FILE* csv_file) {
    // Open handle to the process
    HANDLE process_handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
        FALSE, 
        process_id
    );

    if (!process_handle) return 0;

    char process_name[MAX_PATH];
    HMODULE first_module;
    DWORD bytes_needed;
    
    // Get the process name from its first module
    if (!EnumProcessModules(process_handle, &first_module, sizeof(first_module), &bytes_needed)) {
        CloseHandle(process_handle);
        return 0;
    }

    GetModuleBaseNameA(process_handle, first_module, process_name, sizeof(process_name));

    // Enumerate all modules in the process
    HMODULE modules[1024];
    if (EnumProcessModules(process_handle, modules, sizeof(modules), &bytes_needed)) {
        DWORD num_modules = bytes_needed / sizeof(HMODULE);
        
        char sanitized_process[MAX_PATH * 2];
        char module_path[MAX_PATH];
        char sanitized_path[MAX_PATH * 2];

        sanitize_csv_field(process_name, sanitized_process);

        // Process each module
        for (DWORD i = 0; i < num_modules; i++) {
            if (GetModuleFileNameExA(process_handle, modules[i], module_path, sizeof(module_path))) {
                char* sha256_hash = calculate_sha256(module_path);
                
                sanitize_csv_field(module_path, sanitized_path);
                fprintf(csv_file, "%s,%u,%s,%s\n", 
                    sanitized_process, 
                    process_id, 
                    sanitized_path, 
                    sha256_hash ? sha256_hash : "");
            }
        }
    }

    CloseHandle(process_handle);
    return 1;
}

int main(int argc, char* argv[]) {
    // Verify command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output_csv_file>\n", argv[0]);
        return 1;
    }

    // Open output CSV file
    FILE* csv_file = fopen(argv[1], "w");
    if (!csv_file) {
        perror("Failed to open output file");
        return 1;
    }

    // Write CSV header
    fprintf(csv_file, "Process Name,Process ID,Module Path,SHA256\n");

    // Enumerate all processes
    DWORD processes[1024], bytes_needed;
    if (!EnumProcesses(processes, sizeof(processes), &bytes_needed)) {
        fclose(csv_file);
        return 1;
    }

    // Scan modules for each process
    DWORD num_processes = bytes_needed / sizeof(DWORD);
    for (DWORD i = 0; i < num_processes; i++) {
        scan_process_modules(processes[i], csv_file);
    }

    fclose(csv_file);
    printf("Process module paths saved to %s\n", argv[1]);
    return 0;
}
