/*
 * bof_clr.h - CLR Hosting Interfaces for BOF SDK
 *
 * Provides COM interfaces for hosting the .NET Common Language Runtime (CLR)
 * within BOFs. Compatible with InlineExecute-Assembly and similar tools.
 *
 * Include after bof.h:
 *   #include "bof.h"
 *   #include "bof_clr.h"
 *
 */

#ifndef PYNET_BOF_CLR_H
#define PYNET_BOF_CLR_H

#include <oaidl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * CLR HOSTING GUIDS
 * ===========================================================================*/

static GUID xCLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867, {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}
};

static GUID xIID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}
};

static GUID xIID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}
};

static GUID xCLSID_CorRuntimeHost = {
    0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};

static GUID xIID_ICorRuntimeHost = {
    0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};

static GUID xIID_AppDomain = {
    0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}
};

/* ===========================================================================
 * FORWARD DECLARATIONS
 * ===========================================================================*/

typedef struct _ICLRMetaHost ICLRMetaHost;
typedef struct _ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct _ICorRuntimeHost ICorRuntimeHost;
typedef struct _ICorConfiguration ICorConfiguration;
typedef struct _IGCThreadControl IGCThreadControl;
typedef struct _IGCHostControl IGCHostControl;
typedef struct _IDebuggerThreadControl IDebuggerThreadControl;
typedef struct _AppDomain IAppDomain;
typedef struct _Assembly IAssembly;
typedef struct _Type IType;
typedef struct _Binder IBinder;
typedef struct _MethodInfo IMethodInfo;

typedef void* HDOMAINENUM;

/* ===========================================================================
 * BINDING FLAGS ENUM
 * ===========================================================================*/

typedef enum _BindingFlags {
    BindingFlags_Default             = 0,
    BindingFlags_IgnoreCase          = 1,
    BindingFlags_DeclaredOnly        = 2,
    BindingFlags_Instance            = 4,
    BindingFlags_Static              = 8,
    BindingFlags_Public              = 16,
    BindingFlags_NonPublic           = 32,
    BindingFlags_FlattenHierarchy    = 64,
    BindingFlags_InvokeMethod        = 256,
    BindingFlags_CreateInstance      = 512,
    BindingFlags_GetField            = 1024,
    BindingFlags_SetField            = 2048,
    BindingFlags_GetProperty         = 4096,
    BindingFlags_SetProperty         = 8192,
    BindingFlags_PutDispProperty     = 16384,
    BindingFlags_PutRefDispProperty  = 32768,
    BindingFlags_ExactBinding        = 65536,
    BindingFlags_SuppressChangeType  = 131072,
    BindingFlags_OptionalParamBinding = 262144,
    BindingFlags_IgnoreReturn        = 16777216
} BindingFlags;

/* ===========================================================================
 * FUNCTION POINTER TYPEDEFS
 * ===========================================================================*/

typedef HRESULT(__stdcall* CLRCreateInstanceFnPtr)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
typedef HRESULT(__stdcall* CreateInterfaceFnPtr)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
typedef HRESULT(__stdcall* CallbackThreadSetFnPtr)(void);
typedef HRESULT(__stdcall* CallbackThreadUnsetFnPtr)(void);
typedef void(__stdcall* RuntimeLoadedCallbackFnPtr)(ICLRRuntimeInfo* pRuntimeInfo, CallbackThreadSetFnPtr pfnCallbackThreadSet, CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);

/* ===========================================================================
 * ICLRMetaHost INTERFACE
 * ===========================================================================*/

typedef struct ICLRMetaHostVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICLRMetaHost* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICLRMetaHost* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICLRMetaHost* This);
    HRESULT(STDMETHODCALLTYPE* GetRuntime)(ICLRMetaHost* This, LPCWSTR pwzVersion, REFIID riid, LPVOID* ppRuntime);
    HRESULT(STDMETHODCALLTYPE* GetVersionFromFile)(ICLRMetaHost* This, LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD* pcchBuffer);
    HRESULT(STDMETHODCALLTYPE* EnumerateInstalledRuntimes)(ICLRMetaHost* This, IEnumUnknown** ppEnumerator);
    HRESULT(STDMETHODCALLTYPE* EnumerateLoadedRuntimes)(ICLRMetaHost* This, HANDLE hndProcess, IEnumUnknown** ppEnumerator);
    HRESULT(STDMETHODCALLTYPE* RequestRuntimeLoadedNotification)(ICLRMetaHost* This, RuntimeLoadedCallbackFnPtr pCallbackFunction);
    HRESULT(STDMETHODCALLTYPE* QueryLegacyV2RuntimeBinding)(ICLRMetaHost* This, REFIID riid, LPVOID* ppUnk);
    HRESULT(STDMETHODCALLTYPE* ExitProcess)(ICLRMetaHost* This, INT32 iExitCode);
    END_INTERFACE
} ICLRMetaHostVtbl;

typedef struct _ICLRMetaHost {
    ICLRMetaHostVtbl* lpVtbl;
} ICLRMetaHost;

/* ===========================================================================
 * ICLRRuntimeInfo INTERFACE
 * ===========================================================================*/

typedef struct ICLRRuntimeInfoVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICLRRuntimeInfo* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICLRRuntimeInfo* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICLRRuntimeInfo* This);
    HRESULT(STDMETHODCALLTYPE* GetVersionString)(ICLRRuntimeInfo* This, LPWSTR pwzBuffer, DWORD* pcchBuffer);
    HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)(ICLRRuntimeInfo* This, LPWSTR pwzBuffer, DWORD* pcchBuffer);
    HRESULT(STDMETHODCALLTYPE* IsLoaded)(ICLRRuntimeInfo* This, HANDLE hndProcess, BOOL* pbLoaded);
    HRESULT(STDMETHODCALLTYPE* LoadErrorString)(ICLRRuntimeInfo* This, UINT iResourceID, LPWSTR pwzBuffer, DWORD* pcchBuffer, LONG iLocaleID);
    HRESULT(STDMETHODCALLTYPE* LoadLibrary)(ICLRRuntimeInfo* This, LPCWSTR pwzDllName, HMODULE* phndModule);
    HRESULT(STDMETHODCALLTYPE* GetProcAddress)(ICLRRuntimeInfo* This, LPCSTR pszProcName, LPVOID* ppProc);
    HRESULT(STDMETHODCALLTYPE* GetInterface)(ICLRRuntimeInfo* This, REFCLSID rclsid, REFIID riid, LPVOID* ppUnk);
    HRESULT(STDMETHODCALLTYPE* IsLoadable)(ICLRRuntimeInfo* This, BOOL* pbLoadable);
    HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)(ICLRRuntimeInfo* This, DWORD dwStartupFlags, LPCWSTR pwzHostConfigFile);
    HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)(ICLRRuntimeInfo* This, DWORD* pdwStartupFlags, LPWSTR pwzHostConfigFile, DWORD* pcchHostConfigFile);
    HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)(ICLRRuntimeInfo* This);
    HRESULT(STDMETHODCALLTYPE* IsStarted)(ICLRRuntimeInfo* This, BOOL* pbStarted, DWORD* pdwStartupFlags);
    END_INTERFACE
} ICLRRuntimeInfoVtbl;

typedef struct _ICLRRuntimeInfo {
    ICLRRuntimeInfoVtbl* lpVtbl;
} ICLRRuntimeInfo;

/* ===========================================================================
 * ICorRuntimeHost INTERFACE
 * ===========================================================================*/

typedef struct ICorRuntimeHostVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICorRuntimeHost* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICorRuntimeHost* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICorRuntimeHost* This);
    HRESULT(STDMETHODCALLTYPE* CreateLogicalThreadState)(ICorRuntimeHost* This);
    HRESULT(STDMETHODCALLTYPE* DeleteLogicalThreadState)(ICorRuntimeHost* This);
    HRESULT(STDMETHODCALLTYPE* SwitchInLogicalThreadState)(ICorRuntimeHost* This, DWORD* pFiberCookie);
    HRESULT(STDMETHODCALLTYPE* SwitchOutLogicalThreadState)(ICorRuntimeHost* This, DWORD** pFiberCookie);
    HRESULT(STDMETHODCALLTYPE* LocksHeldByLogicalThread)(ICorRuntimeHost* This, DWORD* pCount);
    HRESULT(STDMETHODCALLTYPE* MapFile)(ICorRuntimeHost* This, HANDLE hFile, HMODULE* hMapAddress);
    HRESULT(STDMETHODCALLTYPE* GetConfiguration)(ICorRuntimeHost* This, ICorConfiguration** pConfiguration);
    HRESULT(STDMETHODCALLTYPE* Start)(ICorRuntimeHost* This);
    HRESULT(STDMETHODCALLTYPE* Stop)(ICorRuntimeHost* This);
    HRESULT(STDMETHODCALLTYPE* CreateDomain)(ICorRuntimeHost* This, LPCWSTR pwzFriendlyName, IUnknown* pIdentityArray, IUnknown** pAppDomain);
    HRESULT(STDMETHODCALLTYPE* GetDefaultDomain)(ICorRuntimeHost* This, IUnknown** pAppDomain);
    HRESULT(STDMETHODCALLTYPE* EnumDomains)(ICorRuntimeHost* This, HDOMAINENUM* hEnum);
    HRESULT(STDMETHODCALLTYPE* NextDomain)(ICorRuntimeHost* This, HDOMAINENUM hEnum, IUnknown** pAppDomain);
    HRESULT(STDMETHODCALLTYPE* CloseEnum)(ICorRuntimeHost* This, HDOMAINENUM hEnum);
    HRESULT(STDMETHODCALLTYPE* CreateDomainEx)(ICorRuntimeHost* This, LPCWSTR pwzFriendlyName, IUnknown* pSetup, IUnknown* pEvidence, IUnknown** pAppDomain);
    HRESULT(STDMETHODCALLTYPE* CreateDomainSetup)(ICorRuntimeHost* This, IUnknown** pAppDomainSetup);
    HRESULT(STDMETHODCALLTYPE* CreateEvidence)(ICorRuntimeHost* This, IUnknown** pEvidence);
    HRESULT(STDMETHODCALLTYPE* UnloadDomain)(ICorRuntimeHost* This, IUnknown* pAppDomain);
    HRESULT(STDMETHODCALLTYPE* CurrentDomain)(ICorRuntimeHost* This, IUnknown** pAppDomain);
    END_INTERFACE
} ICorRuntimeHostVtbl;

typedef struct _ICorRuntimeHost {
    ICorRuntimeHostVtbl* lpVtbl;
} ICorRuntimeHost;

/* ===========================================================================
 * ICorConfiguration INTERFACE
 * ===========================================================================*/

typedef struct ICorConfigurationVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICorConfiguration* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICorConfiguration* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICorConfiguration* This);
    HRESULT(STDMETHODCALLTYPE* SetGCThreadControl)(ICorConfiguration* This, IGCThreadControl* pGCThreadControl);
    HRESULT(STDMETHODCALLTYPE* SetGCHostControl)(ICorConfiguration* This, IGCHostControl* pGCHostControl);
    HRESULT(STDMETHODCALLTYPE* SetDebuggerThreadControl)(ICorConfiguration* This, IDebuggerThreadControl* pDebuggerThreadControl);
    HRESULT(STDMETHODCALLTYPE* AddDebuggerSpecialThread)(ICorConfiguration* This, DWORD dwSpecialThreadId);
    END_INTERFACE
} ICorConfigurationVtbl;

typedef struct _ICorConfiguration {
    ICorConfigurationVtbl* lpVtbl;
} ICorConfiguration;

/* ===========================================================================
 * IGCThreadControl INTERFACE
 * ===========================================================================*/

typedef struct IGCThreadControlVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IGCThreadControl* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IGCThreadControl* This);
    ULONG(STDMETHODCALLTYPE* Release)(IGCThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForSuspension)(IGCThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* SuspensionStarting)(IGCThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* SuspensionEnding)(IGCThreadControl* This, DWORD Generation);
    END_INTERFACE
} IGCThreadControlVtbl;

typedef struct _IGCThreadControl {
    IGCThreadControlVtbl* lpVtbl;
} IGCThreadControl;

/* ===========================================================================
 * IGCHostControl INTERFACE
 * ===========================================================================*/

typedef struct IGCHostControlVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IGCHostControl* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IGCHostControl* This);
    ULONG(STDMETHODCALLTYPE* Release)(IGCHostControl* This);
    HRESULT(STDMETHODCALLTYPE* RequestVirtualMemLimit)(IGCHostControl* This, SIZE_T sztMaxVirtualMemMB, SIZE_T* psztNewMaxVirtualMemMB);
    END_INTERFACE
} IGCHostControlVtbl;

typedef struct _IGCHostControl {
    IGCHostControlVtbl* lpVtbl;
} IGCHostControl;

/* ===========================================================================
 * IDebuggerThreadControl INTERFACE
 * ===========================================================================*/

typedef struct IDebuggerThreadControlVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IDebuggerThreadControl* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IDebuggerThreadControl* This);
    ULONG(STDMETHODCALLTYPE* Release)(IDebuggerThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForDebugger)(IDebuggerThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* ReleaseAllRuntimeThreads)(IDebuggerThreadControl* This);
    HRESULT(STDMETHODCALLTYPE* StartBlockingForDebugger)(IDebuggerThreadControl* This, DWORD dwUnused);
    END_INTERFACE
} IDebuggerThreadControlVtbl;

typedef struct _IDebuggerThreadControl {
    IDebuggerThreadControlVtbl* lpVtbl;
} IDebuggerThreadControl;

/* ===========================================================================
 * IAppDomain INTERFACE
 * ===========================================================================*/

typedef struct _AppDomainVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IAppDomain* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IAppDomain* This);
    ULONG(STDMETHODCALLTYPE* Release)(IAppDomain* This);
    /* IDispatch */
    HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(IAppDomain* This, UINT* pctinfo);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(IAppDomain* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(IAppDomain* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT(STDMETHODCALLTYPE* Invoke)(IAppDomain* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    /* _AppDomain methods - placeholders for vtable offset */
    HRESULT(STDMETHODCALLTYPE* get_ToString)(IAppDomain* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Equals)(IAppDomain* This, VARIANT other, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetHashCode)(IAppDomain* This, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType)(IAppDomain* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* InitializeLifetimeService)(IAppDomain* This, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetLifetimeService)(IAppDomain* This, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_Evidence)(IAppDomain* This, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* add_DomainUnload)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_DomainUnload)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_AssemblyLoad)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_AssemblyLoad)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_ProcessExit)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_ProcessExit)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_TypeResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_TypeResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_ResourceResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_ResourceResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_AssemblyResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_AssemblyResolve)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* add_UnhandledException)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_UnhandledException)(IAppDomain* This, void* value);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly)(IAppDomain* This, void* name, INT32 access, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_2)(IAppDomain* This, void* name, INT32 access, BSTR dir, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_3)(IAppDomain* This, void* name, INT32 access, void* evidence, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_4)(IAppDomain* This, void* name, INT32 access, void* requiredPermissions, void* optionalPermissions, void* refusedPermissions, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_5)(IAppDomain* This, void* name, INT32 access, BSTR dir, void* evidence, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_6)(IAppDomain* This, void* name, INT32 access, BSTR dir, void* requiredPermissions, void* optionalPermissions, void* refusedPermissions, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_7)(IAppDomain* This, void* name, INT32 access, void* evidence, void* requiredPermissions, void* optionalPermissions, void* refusedPermissions, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_8)(IAppDomain* This, void* name, INT32 access, BSTR dir, void* evidence, void* requiredPermissions, void* optionalPermissions, void* refusedPermissions, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly_9)(IAppDomain* This, void* name, INT32 access, BSTR dir, void* evidence, void* requiredPermissions, void* optionalPermissions, void* refusedPermissions, VARIANT_BOOL isSynchronized, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance)(IAppDomain* This, BSTR assemblyName, BSTR typeName, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstanceFrom)(IAppDomain* This, BSTR assemblyFile, BSTR typeName, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance_2)(IAppDomain* This, BSTR assemblyName, BSTR typeName, SAFEARRAY* activationAttributes, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstanceFrom_2)(IAppDomain* This, BSTR assemblyFile, BSTR typeName, SAFEARRAY* activationAttributes, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance_3)(IAppDomain* This, BSTR assemblyName, BSTR typeName, VARIANT_BOOL ignoreCase, INT32 bindingAttr, IBinder* Binder, SAFEARRAY* args, void* culture, SAFEARRAY* activationAttributes, void* securityAttributes, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstanceFrom_3)(IAppDomain* This, BSTR assemblyFile, BSTR typeName, VARIANT_BOOL ignoreCase, INT32 bindingAttr, IBinder* Binder, SAFEARRAY* args, void* culture, SAFEARRAY* activationAttributes, void* securityAttributes, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load)(IAppDomain* This, void* assemblyRef, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_2)(IAppDomain* This, BSTR assemblyString, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_3)(IAppDomain* This, SAFEARRAY* rawAssembly, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_4)(IAppDomain* This, SAFEARRAY* rawAssembly, SAFEARRAY* rawSymbolStore, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_5)(IAppDomain* This, SAFEARRAY* rawAssembly, SAFEARRAY* rawSymbolStore, void* securityEvidence, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_6)(IAppDomain* This, void* assemblyRef, void* assemblySecurity, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* Load_7)(IAppDomain* This, BSTR assemblyString, void* assemblySecurity, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* ExecuteAssembly)(IAppDomain* This, BSTR assemblyFile, void* assemblySecurity, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* ExecuteAssembly_2)(IAppDomain* This, BSTR assemblyFile, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* ExecuteAssembly_3)(IAppDomain* This, BSTR assemblyFile, void* assemblySecurity, SAFEARRAY* args, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_FriendlyName)(IAppDomain* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_BaseDirectory)(IAppDomain* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_RelativeSearchPath)(IAppDomain* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_ShadowCopyFiles)(IAppDomain* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetAssemblies)(IAppDomain* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* AppendPrivatePath)(IAppDomain* This, BSTR Path);
    HRESULT(STDMETHODCALLTYPE* ClearPrivatePath)(IAppDomain* This);
    HRESULT(STDMETHODCALLTYPE* SetShadowCopyPath)(IAppDomain* This, BSTR s);
    HRESULT(STDMETHODCALLTYPE* ClearShadowCopyPath)(IAppDomain* This);
    HRESULT(STDMETHODCALLTYPE* SetCachePath)(IAppDomain* This, BSTR s);
    HRESULT(STDMETHODCALLTYPE* SetData)(IAppDomain* This, BSTR name, VARIANT data);
    HRESULT(STDMETHODCALLTYPE* GetData)(IAppDomain* This, BSTR name, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* SetAppDomainPolicy)(IAppDomain* This, void* domainPolicy);
    HRESULT(STDMETHODCALLTYPE* SetThreadPrincipal)(IAppDomain* This, void* principal);
    HRESULT(STDMETHODCALLTYPE* SetPrincipalPolicy)(IAppDomain* This, INT32 policy);
    HRESULT(STDMETHODCALLTYPE* DoCallBack)(IAppDomain* This, void* theDelegate);
    HRESULT(STDMETHODCALLTYPE* get_DynamicDirectory)(IAppDomain* This, BSTR* pRetVal);
    END_INTERFACE
} AppDomainVtbl;

typedef struct _AppDomain {
    AppDomainVtbl* lpVtbl;
} AppDomain;

/* ===========================================================================
 * IAssembly INTERFACE
 * ===========================================================================*/

typedef struct _AssemblyVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IAssembly* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IAssembly* This);
    ULONG(STDMETHODCALLTYPE* Release)(IAssembly* This);
    /* IDispatch */
    HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(IAssembly* This, UINT* pctinfo);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(IAssembly* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(IAssembly* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT(STDMETHODCALLTYPE* Invoke)(IAssembly* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    /* _Assembly methods */
    HRESULT(STDMETHODCALLTYPE* get_ToString)(IAssembly* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Equals)(IAssembly* This, VARIANT other, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetHashCode)(IAssembly* This, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType)(IAssembly* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_CodeBase)(IAssembly* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_EscapedCodeBase)(IAssembly* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetName)(IAssembly* This, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetName_2)(IAssembly* This, VARIANT_BOOL copiedName, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_FullName)(IAssembly* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_EntryPoint)(IAssembly* This, IMethodInfo** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType_2)(IAssembly* This, BSTR name, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType_3)(IAssembly* This, BSTR name, VARIANT_BOOL throwOnError, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetExportedTypes)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetTypes)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetManifestResourceStream)(IAssembly* This, IType* type, BSTR name, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetManifestResourceStream_2)(IAssembly* This, BSTR name, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetFile)(IAssembly* This, BSTR name, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetFiles)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetFiles_2)(IAssembly* This, VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetManifestResourceNames)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetManifestResourceInfo)(IAssembly* This, BSTR resourceName, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_Location)(IAssembly* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_Evidence)(IAssembly* This, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetCustomAttributes)(IAssembly* This, IType* attributeType, VARIANT_BOOL inherit, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetCustomAttributes_2)(IAssembly* This, VARIANT_BOOL inherit, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* IsDefined)(IAssembly* This, IType* attributeType, VARIANT_BOOL inherit, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetObjectData)(IAssembly* This, void* info, void* Context);
    HRESULT(STDMETHODCALLTYPE* add_ModuleResolve)(IAssembly* This, void* value);
    HRESULT(STDMETHODCALLTYPE* remove_ModuleResolve)(IAssembly* This, void* value);
    HRESULT(STDMETHODCALLTYPE* GetType_4)(IAssembly* This, BSTR name, VARIANT_BOOL throwOnError, VARIANT_BOOL ignoreCase, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetSatelliteAssembly)(IAssembly* This, void* culture, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetSatelliteAssembly_2)(IAssembly* This, void* culture, void* version, IAssembly** pRetVal);
    HRESULT(STDMETHODCALLTYPE* LoadModule)(IAssembly* This, BSTR moduleName, SAFEARRAY* rawModule, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* LoadModule_2)(IAssembly* This, BSTR moduleName, SAFEARRAY* rawModule, SAFEARRAY* rawSymbolStore, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance_2)(IAssembly* This, BSTR typeName, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance_3)(IAssembly* This, BSTR typeName, VARIANT_BOOL ignoreCase, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* CreateInstance_4)(IAssembly* This, BSTR typeName, VARIANT_BOOL ignoreCase, INT32 bindingAttr, IBinder* Binder, SAFEARRAY* args, void* culture, SAFEARRAY* activationAttributes, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetLoadedModules)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetLoadedModules_2)(IAssembly* This, VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetModules)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetModules_2)(IAssembly* This, VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetModule)(IAssembly* This, BSTR name, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetReferencedAssemblies)(IAssembly* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_GlobalAssemblyCache)(IAssembly* This, VARIANT_BOOL* pRetVal);
    END_INTERFACE
} AssemblyVtbl;

typedef struct _Assembly {
    AssemblyVtbl* lpVtbl;
} Assembly;

/* ===========================================================================
 * IMethodInfo INTERFACE
 * ===========================================================================*/

typedef struct _MethodInfoVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IMethodInfo* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IMethodInfo* This);
    ULONG(STDMETHODCALLTYPE* Release)(IMethodInfo* This);
    /* IDispatch */
    HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(IMethodInfo* This, UINT* pctinfo);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(IMethodInfo* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(IMethodInfo* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT(STDMETHODCALLTYPE* Invoke_OnDispatch)(IMethodInfo* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    /* _MethodInfo methods */
    HRESULT(STDMETHODCALLTYPE* get_ToString)(IMethodInfo* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Equals)(IMethodInfo* This, VARIANT other, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetHashCode)(IMethodInfo* This, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType)(IMethodInfo* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_MemberType)(IMethodInfo* This, INT32* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_name)(IMethodInfo* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_DeclaringType)(IMethodInfo* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_ReflectedType)(IMethodInfo* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetCustomAttributes)(IMethodInfo* This, IType* attributeType, VARIANT_BOOL inherit, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetCustomAttributes_2)(IMethodInfo* This, VARIANT_BOOL inherit, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* IsDefined)(IMethodInfo* This, IType* attributeType, VARIANT_BOOL inherit, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetParameters)(IMethodInfo* This, SAFEARRAY** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetMethodImplementationFlags)(IMethodInfo* This, INT32* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_MethodHandle)(IMethodInfo* This, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_Attributes)(IMethodInfo* This, INT32* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_CallingConvention)(IMethodInfo* This, INT32* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Invoke)(IMethodInfo* This, VARIANT obj, INT32 invokeAttr, IBinder* Binder, SAFEARRAY* parameters, void* culture, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsPublic)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsPrivate)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsFamily)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsAssembly)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsFamilyAndAssembly)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsFamilyOrAssembly)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsStatic)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsFinal)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsVirtual)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsHideBySig)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsAbstract)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsSpecialName)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_IsConstructor)(IMethodInfo* This, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Invoke_2)(IMethodInfo* This, VARIANT obj, SAFEARRAY* parameters, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Invoke_3)(IMethodInfo* This, VARIANT obj, INT32 invokeAttr, IBinder* Binder, SAFEARRAY* parameters, void* culture, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_returnType)(IMethodInfo* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* get_ReturnTypeCustomAttributes)(IMethodInfo* This, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetBaseDefinition)(IMethodInfo* This, IMethodInfo** pRetVal);
    END_INTERFACE
} MethodInfoVtbl;

typedef struct _MethodInfo {
    MethodInfoVtbl* lpVtbl;
} MethodInfo;

/* ===========================================================================
 * IType INTERFACE (simplified - commonly used methods)
 * ===========================================================================*/

typedef struct _TypeVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IType* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IType* This);
    ULONG(STDMETHODCALLTYPE* Release)(IType* This);
    /* IDispatch */
    HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(IType* This, UINT* pctinfo);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(IType* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(IType* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT(STDMETHODCALLTYPE* Invoke)(IType* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    /* _Type methods - minimal set for InvokeMember */
    HRESULT(STDMETHODCALLTYPE* get_ToString)(IType* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Equals)(IType* This, VARIANT other, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetHashCode)(IType* This, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType)(IType* This, IType** pRetVal);
    /* ... many intermediate methods omitted for brevity ... */
    /* These are placeholders to maintain vtable alignment */
    void* reserved[80];
    HRESULT(STDMETHODCALLTYPE* InvokeMember_3)(IType* This, BSTR name, BindingFlags invokeAttr, IBinder* Binder, VARIANT Target, SAFEARRAY* args, VARIANT* pRetVal);
    END_INTERFACE
} TypeVtbl;

typedef struct _Type {
    TypeVtbl* lpVtbl;
} Type;

/* ===========================================================================
 * IBinder INTERFACE
 * ===========================================================================*/

typedef struct _BinderVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IBinder* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IBinder* This);
    ULONG(STDMETHODCALLTYPE* Release)(IBinder* This);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(IBinder* This, UINT* pctinfo);
    HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(IBinder* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(IBinder* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT(STDMETHODCALLTYPE* Invoke)(IBinder* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    HRESULT(STDMETHODCALLTYPE* get_ToString)(IBinder* This, BSTR* pRetVal);
    HRESULT(STDMETHODCALLTYPE* Equals)(IBinder* This, VARIANT other, VARIANT_BOOL* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetHashCode)(IBinder* This, LONG* pRetVal);
    HRESULT(STDMETHODCALLTYPE* GetType)(IBinder* This, IType** pRetVal);
    HRESULT(STDMETHODCALLTYPE* BindToMethod)(IBinder* This, INT32 bindingAttr, SAFEARRAY* match, VARIANT* args, SAFEARRAY* modifiers, void* culture, SAFEARRAY* names, VARIANT* state, IMethodInfo** pRetVal);
    HRESULT(STDMETHODCALLTYPE* BindToField)(IBinder* This, INT32 bindingAttr, SAFEARRAY* match, VARIANT value, void* culture, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* SelectMethod)(IBinder* This, INT32 bindingAttr, SAFEARRAY* match, SAFEARRAY* types, SAFEARRAY* modifiers, IMethodInfo** pRetVal);
    HRESULT(STDMETHODCALLTYPE* SelectProperty)(IBinder* This, INT32 bindingAttr, SAFEARRAY* match, IType* returnType, SAFEARRAY* indexes, SAFEARRAY* modifiers, void** pRetVal);
    HRESULT(STDMETHODCALLTYPE* ChangeType)(IBinder* This, VARIANT value, IType* type, void* culture, VARIANT* pRetVal);
    HRESULT(STDMETHODCALLTYPE* ReorderArgumentArray)(IBinder* This, VARIANT* args, VARIANT state);
    END_INTERFACE
} BinderVtbl;

typedef struct _Binder {
    BinderVtbl* lpVtbl;
} Binder;

/* ===========================================================================
 * HELPER MACROS
 * ===========================================================================*/

#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#endif

#ifndef FAILED
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#endif

#ifndef SAFE_RELEASE
#define SAFE_RELEASE(punk) \
    if ((punk) != NULL) { (punk)->lpVtbl->Release(punk); (punk) = NULL; }
#endif

#ifdef __cplusplus
}
#endif

#endif /* PYNET_BOF_CLR_H */
