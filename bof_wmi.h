#ifndef PYNET_BOF_WMI_H
#define PYNET_BOF_WMI_H

/*
 * bof_wmi.h - WMI COM interface definitions for PyNet BOFs
 *
 * Include AFTER bof.h
 * Provides interface definitions for WMI remote execution via DCOM
 */

// ============================================================================
// DCOM Security Constants
// ============================================================================

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT           10
#endif
#ifndef RPC_C_AUTHN_DEFAULT
#define RPC_C_AUTHN_DEFAULT         0xFFFFFFFF
#endif
#ifndef RPC_C_AUTHZ_NONE
#define RPC_C_AUTHZ_NONE            0
#endif
#ifndef RPC_C_AUTHZ_DEFAULT
#define RPC_C_AUTHZ_DEFAULT         0xFFFFFFFF
#endif
#ifndef RPC_C_AUTHN_LEVEL_DEFAULT
#define RPC_C_AUTHN_LEVEL_DEFAULT   0
#endif
#ifndef RPC_C_AUTHN_LEVEL_PKT_PRIVACY
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6
#endif
#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#endif
#ifndef EOAC_NONE
#define EOAC_NONE                   0
#endif

// COM context flags
#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER        0x1
#endif
#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER         0x4
#endif

// COINIT flags
#ifndef COINIT_MULTITHREADED
#define COINIT_MULTITHREADED        0x0
#endif
#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED    0x2
#endif

// WBEM flags
#define WBEM_FLAG_RETURN_WBEM_COMPLETE  0x00
#define WBEM_FLAG_SPAWN_INSTANCE        0x01

// VARIANT types
#ifndef VT_BSTR
#define VT_BSTR     8
#endif
#ifndef VT_I4
#define VT_I4       3
#endif
#ifndef VT_NULL
#define VT_NULL     1
#endif

// ============================================================================
// GUIDs - WMI Classes and Interfaces
// ============================================================================

// CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24}
static const GUID CLSID_WbemLocator = {
    0x4590F811, 0x1D3A, 0x11D0,
    {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// IID_IWbemLocator: {DC12A687-737F-11CF-884D-00AA004B2E24}
static const GUID IID_IWbemLocator = {
    0xDC12A687, 0x737F, 0x11CF,
    {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// IID_IWbemServices: {9556DC99-828C-11CF-A37E-00AA003240C7}
static const GUID IID_IWbemServices = {
    0x9556DC99, 0x828C, 0x11CF,
    {0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7}
};

// IID_IWbemClassObject: {DC12A681-737F-11CF-884D-00AA004B2E24}
static const GUID IID_IWbemClassObject = {
    0xDC12A681, 0x737F, 0x11CF,
    {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// ============================================================================
// Forward Declarations
// ============================================================================

typedef struct IWbemLocator IWbemLocator;
typedef struct IWbemServices IWbemServices;
typedef struct IWbemClassObject IWbemClassObject;
typedef struct IWbemContext IWbemContext;
typedef struct IWbemCallResult IWbemCallResult;
typedef struct IWbemQualifierSet IWbemQualifierSet;
typedef struct IWbemObjectSink IWbemObjectSink;

// ============================================================================
// IWbemLocator Interface
// ============================================================================

typedef struct IWbemLocatorVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IWbemLocator* This,
        REFIID riid,
        void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(
        IWbemLocator* This);
    ULONG (STDMETHODCALLTYPE *Release)(
        IWbemLocator* This);

    // IWbemLocator
    HRESULT (STDMETHODCALLTYPE *ConnectServer)(
        IWbemLocator* This,
        BSTR strNetworkResource,    // \\server\root\cimv2
        BSTR strUser,               // DOMAIN\user or user
        BSTR strPassword,           // password
        BSTR strLocale,             // NULL for default
        LONG lSecurityFlags,        // 0
        BSTR strAuthority,          // NULL or "ntlmdomain:DOMAIN"
        IWbemContext* pCtx,         // NULL
        IWbemServices** ppNamespace);
} IWbemLocatorVtbl;

struct IWbemLocator {
    IWbemLocatorVtbl* lpVtbl;
};

// ============================================================================
// IWbemServices Interface
// ============================================================================

typedef struct IWbemServicesVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IWbemServices* This,
        REFIID riid,
        void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(
        IWbemServices* This);
    ULONG (STDMETHODCALLTYPE *Release)(
        IWbemServices* This);

    // IWbemServices - we only need a subset
    HRESULT (STDMETHODCALLTYPE *OpenNamespace)(
        IWbemServices* This,
        BSTR strNamespace,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemServices** ppWorkingNamespace,
        IWbemCallResult** ppResult);

    HRESULT (STDMETHODCALLTYPE *CancelAsyncCall)(
        IWbemServices* This,
        IWbemObjectSink* pSink);

    HRESULT (STDMETHODCALLTYPE *QueryObjectSink)(
        IWbemServices* This,
        LONG lFlags,
        IWbemObjectSink** ppResponseHandler);

    HRESULT (STDMETHODCALLTYPE *GetObject)(
        IWbemServices* This,
        BSTR strObjectPath,         // "Win32_Process"
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemClassObject** ppObject,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *GetObjectAsync)(
        IWbemServices* This,
        BSTR strObjectPath,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *PutClass)(
        IWbemServices* This,
        IWbemClassObject* pObject,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *PutClassAsync)(
        IWbemServices* This,
        IWbemClassObject* pObject,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *DeleteClass)(
        IWbemServices* This,
        BSTR strClass,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *DeleteClassAsync)(
        IWbemServices* This,
        BSTR strClass,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *CreateClassEnum)(
        IWbemServices* This,
        BSTR strSuperclass,
        LONG lFlags,
        IWbemContext* pCtx,
        void** ppEnum);

    HRESULT (STDMETHODCALLTYPE *CreateClassEnumAsync)(
        IWbemServices* This,
        BSTR strSuperclass,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *PutInstance)(
        IWbemServices* This,
        IWbemClassObject* pInst,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *PutInstanceAsync)(
        IWbemServices* This,
        IWbemClassObject* pInst,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *DeleteInstance)(
        IWbemServices* This,
        BSTR strObjectPath,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *DeleteInstanceAsync)(
        IWbemServices* This,
        BSTR strObjectPath,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *CreateInstanceEnum)(
        IWbemServices* This,
        BSTR strFilter,
        LONG lFlags,
        IWbemContext* pCtx,
        void** ppEnum);

    HRESULT (STDMETHODCALLTYPE *CreateInstanceEnumAsync)(
        IWbemServices* This,
        BSTR strFilter,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *ExecQuery)(
        IWbemServices* This,
        BSTR strQueryLanguage,
        BSTR strQuery,
        LONG lFlags,
        IWbemContext* pCtx,
        void** ppEnum);

    HRESULT (STDMETHODCALLTYPE *ExecQueryAsync)(
        IWbemServices* This,
        BSTR strQueryLanguage,
        BSTR strQuery,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *ExecNotificationQuery)(
        IWbemServices* This,
        BSTR strQueryLanguage,
        BSTR strQuery,
        LONG lFlags,
        IWbemContext* pCtx,
        void** ppEnum);

    HRESULT (STDMETHODCALLTYPE *ExecNotificationQueryAsync)(
        IWbemServices* This,
        BSTR strQueryLanguage,
        BSTR strQuery,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler);

    HRESULT (STDMETHODCALLTYPE *ExecMethod)(
        IWbemServices* This,
        BSTR strObjectPath,         // "Win32_Process"
        BSTR strMethodName,         // "Create"
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemClassObject* pInParams,
        IWbemClassObject** ppOutParams,
        IWbemCallResult** ppCallResult);

    HRESULT (STDMETHODCALLTYPE *ExecMethodAsync)(
        IWbemServices* This,
        BSTR strObjectPath,
        BSTR strMethodName,
        LONG lFlags,
        IWbemContext* pCtx,
        IWbemClassObject* pInParams,
        IWbemObjectSink* pResponseHandler);
} IWbemServicesVtbl;

struct IWbemServices {
    IWbemServicesVtbl* lpVtbl;
};

// ============================================================================
// IWbemClassObject Interface
// ============================================================================

typedef struct IWbemClassObjectVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IWbemClassObject* This,
        REFIID riid,
        void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(
        IWbemClassObject* This);
    ULONG (STDMETHODCALLTYPE *Release)(
        IWbemClassObject* This);

    // IWbemClassObject
    HRESULT (STDMETHODCALLTYPE *GetQualifierSet)(
        IWbemClassObject* This,
        IWbemQualifierSet** ppQualSet);

    HRESULT (STDMETHODCALLTYPE *Get)(
        IWbemClassObject* This,
        LPCWSTR wszName,
        LONG lFlags,
        VARIANT* pVal,
        LONG* pType,
        LONG* plFlavor);

    HRESULT (STDMETHODCALLTYPE *Put)(
        IWbemClassObject* This,
        LPCWSTR wszName,
        LONG lFlags,
        VARIANT* pVal,
        LONG Type);

    HRESULT (STDMETHODCALLTYPE *Delete)(
        IWbemClassObject* This,
        LPCWSTR wszName);

    HRESULT (STDMETHODCALLTYPE *GetNames)(
        IWbemClassObject* This,
        LPCWSTR wszQualifierName,
        LONG lFlags,
        VARIANT* pQualifierVal,
        SAFEARRAY** pNames);

    HRESULT (STDMETHODCALLTYPE *BeginEnumeration)(
        IWbemClassObject* This,
        LONG lEnumFlags);

    HRESULT (STDMETHODCALLTYPE *Next)(
        IWbemClassObject* This,
        LONG lFlags,
        BSTR* strName,
        VARIANT* pVal,
        LONG* pType,
        LONG* plFlavor);

    HRESULT (STDMETHODCALLTYPE *EndEnumeration)(
        IWbemClassObject* This);

    HRESULT (STDMETHODCALLTYPE *GetPropertyQualifierSet)(
        IWbemClassObject* This,
        LPCWSTR wszProperty,
        IWbemQualifierSet** ppQualSet);

    HRESULT (STDMETHODCALLTYPE *Clone)(
        IWbemClassObject* This,
        IWbemClassObject** ppCopy);

    HRESULT (STDMETHODCALLTYPE *GetObjectText)(
        IWbemClassObject* This,
        LONG lFlags,
        BSTR* pstrObjectText);

    HRESULT (STDMETHODCALLTYPE *SpawnDerivedClass)(
        IWbemClassObject* This,
        LONG lFlags,
        IWbemClassObject** ppNewClass);

    HRESULT (STDMETHODCALLTYPE *SpawnInstance)(
        IWbemClassObject* This,
        LONG lFlags,
        IWbemClassObject** ppNewInstance);

    HRESULT (STDMETHODCALLTYPE *CompareTo)(
        IWbemClassObject* This,
        LONG lFlags,
        IWbemClassObject* pCompareTo);

    HRESULT (STDMETHODCALLTYPE *GetPropertyOrigin)(
        IWbemClassObject* This,
        LPCWSTR wszName,
        BSTR* pstrClassName);

    HRESULT (STDMETHODCALLTYPE *InheritsFrom)(
        IWbemClassObject* This,
        LPCWSTR strAncestor);

    HRESULT (STDMETHODCALLTYPE *GetMethod)(
        IWbemClassObject* This,
        LPCWSTR wszName,
        LONG lFlags,
        IWbemClassObject** ppInSignature,
        IWbemClassObject** ppOutSignature);

    HRESULT (STDMETHODCALLTYPE *PutMethod)(
        IWbemClassObject* This,
        LPCWSTR wszName,
        LONG lFlags,
        IWbemClassObject* pInSignature,
        IWbemClassObject* pOutSignature);

    HRESULT (STDMETHODCALLTYPE *DeleteMethod)(
        IWbemClassObject* This,
        LPCWSTR wszName);

    HRESULT (STDMETHODCALLTYPE *BeginMethodEnumeration)(
        IWbemClassObject* This,
        LONG lEnumFlags);

    HRESULT (STDMETHODCALLTYPE *NextMethod)(
        IWbemClassObject* This,
        LONG lFlags,
        BSTR* pstrName,
        IWbemClassObject** ppInSignature,
        IWbemClassObject** ppOutSignature);

    HRESULT (STDMETHODCALLTYPE *EndMethodEnumeration)(
        IWbemClassObject* This);

    HRESULT (STDMETHODCALLTYPE *GetMethodQualifierSet)(
        IWbemClassObject* This,
        LPCWSTR wszMethod,
        IWbemQualifierSet** ppQualSet);

    HRESULT (STDMETHODCALLTYPE *GetMethodOrigin)(
        IWbemClassObject* This,
        LPCWSTR wszMethodName,
        BSTR* pstrClassName);
} IWbemClassObjectVtbl;

struct IWbemClassObject {
    IWbemClassObjectVtbl* lpVtbl;
};

// ============================================================================
// Helper Macros
// ============================================================================

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)

// Safe release macro
#define SAFE_RELEASE(p) do { if ((p)) { (p)->lpVtbl->Release(p); (p) = NULL; } } while(0)

// Safe BSTR free macro
#define SAFE_BSTR_FREE(b) do { if ((b)) { SysFreeString(b); (b) = NULL; } } while(0)

#endif /* PYNET_BOF_WMI_H */
