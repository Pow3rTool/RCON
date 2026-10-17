// RCON's opt-in console sign-in provider. It has no stored credentials and no
// network client. Only a live, local SYSTEM RCON service can supply a one-use
// credential, and only at an empty console. Built-in providers remain intact.
#define SECURITY_WIN32
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <wtsapi32.h>
#include <shlwapi.h>
#include <winsvc.h>
#include <new>
#include <cwchar>

static const CLSID ProviderID = {0x264b7708,0x953d,0x470a,{0x80,0xb9,0x20,0x9f,0x00,0x86,0x23,0xb2}};
static HINSTANCE module;
static LONG objects;
#pragma pack(push,1)
struct Ticket { DWORD magic, session; ULONGLONG expires; WCHAR user[32], domain[64], password[33]; };
#pragma pack(pop)
static_assert(sizeof(Ticket)==274, "Go protocol must match");

static bool EmptyConsole(DWORD session) {
    if (WTSGetActiveConsoleSessionId()!=session) return false;
    PWTS_SESSION_INFOW rows=nullptr; DWORD count=0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&rows,&count)) return false;
    bool empty=true;
    for (DWORD i=0;i<count;i++) {
        if (rows[i].SessionId==0 || rows[i].State==WTSListen) continue;
        LPWSTR name=nullptr; DWORD bytes=0;
        if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, rows[i].SessionId, WTSUserName, &name,&bytes)) { empty=false; break; }
        if (name && *name) empty=false;
        WTSFreeMemory(name);
        if (!empty) break;
    }
    WTSFreeMemory(rows); return empty;
}
static bool TrustedServer(HANDLE pipe) {
    ULONG pid=0;
    if (!GetNamedPipeServerProcessId(pipe,&pid)) return false;
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service=OpenServiceW(manager,L"Pow3rToolRCON",SERVICE_QUERY_STATUS);
    SERVICE_STATUS_PROCESS status={}; DWORD bytes=0;
    bool ok=service && QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&bytes)
        && status.dwCurrentState==SERVICE_RUNNING && status.dwProcessId==pid;
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    return ok;
}

// Bounded metadata-only diagnostics. C:\RCON\state is SYSTEM/Admin-only.
static void Audit(const WCHAR* stage, HRESULT status=S_OK) {
    HANDLE f=CreateFileW(L"C:\\RCON\\state\\recovery-provider.log",FILE_APPEND_DATA|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size={}; if(GetFileSizeEx(f,&size) && size.QuadPart>1024*1024) { CloseHandle(f); return; }
    SYSTEMTIME now={}; GetSystemTime(&now);
    WCHAR line[256]; int n=swprintf_s(line,L"%04u-%02u-%02uT%02u:%02u:%02uZ pid=%lu %ls status=0x%08lx\r\n",now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,GetCurrentProcessId(),stage,static_cast<ULONG>(status));
    DWORD written=0; if(n>0) WriteFile(f,line,n*sizeof(WCHAR),&written,nullptr); CloseHandle(f);
}

class Provider final : public ICredentialProvider, public ICredentialProviderCredential {
    LONG refs=1;
    ICredentialProviderEvents* events=nullptr;
    UINT_PTR adviseContext=0;
    HWND window=nullptr;
    DWORD session=0;
    Ticket ticket={};
    bool ready=false;
    void Clear() { SecureZeroMemory(&ticket,sizeof(ticket)); ready=false; }
    static LRESULT CALLBACK WindowProc(HWND hwnd,UINT msg,WPARAM w,LPARAM l) {
        Provider* p=reinterpret_cast<Provider*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
        if (msg==WM_NCCREATE) { p=static_cast<Provider*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams); SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(p)); }
        if (msg==WM_TIMER && p) { p->Poll(); return 0; }
        return DefWindowProcW(hwnd,msg,w,l);
    }
    void Poll() {
        if (ready) { if (GetTickCount64()>ticket.expires || !EmptyConsole(session)) Clear(); return; }
        if (!events || !EmptyConsole(session)) return;
        WCHAR name[128]; swprintf_s(name,L"\\\\.\\pipe\\Pow3rTool-RCON-recovery-v1-%lu",session);
        HANDLE pipe=CreateFileW(name,GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
        if (pipe==INVALID_HANDLE_VALUE) return;
        if (!TrustedServer(pipe)) { CloseHandle(pipe); return; }
        OVERLAPPED ov={}; ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if (!ov.hEvent) { CloseHandle(pipe); return; }
        DWORD bytes=0; bool ok=ReadFile(pipe,&ticket,sizeof(ticket),&bytes,&ov)!=FALSE;
        if (!ok && GetLastError()==ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent,1000)==WAIT_OBJECT_0) ok=GetOverlappedResult(pipe,&ov,&bytes,FALSE)!=FALSE;
            else { CancelIoEx(pipe,&ov); GetOverlappedResult(pipe,&ov,&bytes,TRUE); }
        }
        CloseHandle(ov.hEvent); CloseHandle(pipe);
        ULONGLONG now=GetTickCount64();
        if (!ok || bytes!=sizeof(ticket) || ticket.magic!=0x52434c31 || ticket.session!=session || ticket.expires<now || ticket.expires>now+11000
            || ticket.user[31]!=0 || ticket.domain[63]!=0 || ticket.password[32]!=0 || wcslen(ticket.password)!=32
            || wcscmp(ticket.user,L"rcon-operator")!=0 || !EmptyConsole(session)) { Clear(); return; }
        ready=true; Audit(L"ticket-accepted");
        // Runs on LogonUI's own apartment via its message loop, not an unmarshal'd
        // COM callback from a background thread.
        events->CredentialsChanged(adviseContext);
    }
public:
    Provider() { InterlockedIncrement(&objects); ProcessIdToSessionId(GetCurrentProcessId(),&session); }
    ~Provider() { UnAdvise(); Clear(); InterlockedDecrement(&objects); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        *out=nullptr;
        if (iid==IID_IUnknown || iid==IID_ICredentialProvider) *out=static_cast<ICredentialProvider*>(this);
        else if (iid==IID_ICredentialProviderCredential) *out=static_cast<ICredentialProviderCredential*>(this);
        if (!*out) return E_NOINTERFACE; AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override { LONG r=InterlockedDecrement(&refs); if (!r) delete this; return r; }
    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage,DWORD) override { return usage==CPUS_LOGON ? S_OK : E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* e,UINT_PTR context) override {
        Audit(L"provider-advised"); UnAdvise(); events=e; events->AddRef(); adviseContext=context;
        WNDCLASSW cls={}; cls.lpfnWndProc=WindowProc; cls.hInstance=module; cls.lpszClassName=L"RconRecoveryProviderV1";
        RegisterClassW(&cls);
        window=CreateWindowExW(0,cls.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,module,this);
        if (!window) return HRESULT_FROM_WIN32(GetLastError());
        SetTimer(window,1,250,nullptr); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        if (window) { KillTimer(window,1); DestroyWindow(window); window=nullptr; }
        if (events) { events->Release(); events=nullptr; } Clear(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override { *count=1; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD i,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override {
        *out=nullptr; if (i) return E_INVALIDARG;
        auto d=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!d) return E_OUTOFMEMORY; ZeroMemory(d,sizeof(*d)); d->dwFieldID=0; d->cpft=CPFT_LARGE_TEXT;
        HRESULT hr=SHStrDupW(L"RCON recovery",&d->pszLabel); if (FAILED(hr)) { CoTaskMemFree(d); return hr; } *out=d; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count,DWORD* def,BOOL* autologon) override {
        if (ready && (GetTickCount64()>ticket.expires || !EmptyConsole(session))) Clear();
        *count=ready ? 1 : 0; *def=ready ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT; *autologon=ready; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD i,ICredentialProviderCredential** out) override {
        *out=nullptr; if (i || !ready) return E_INVALIDARG; *out=static_cast<ICredentialProviderCredential*>(this); AddRef(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* autoLogon) override { *autoLogon=ready; return S_OK; }
    HRESULT STDMETHODCALLTYPE SetDeselected() override { Clear(); return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldState(DWORD i,CREDENTIAL_PROVIDER_FIELD_STATE* s,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* f) override { if(i) return E_INVALIDARG; *s=CPFS_DISPLAY_IN_BOTH; *f=CPFIS_NONE; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetStringValue(DWORD i,PWSTR* value) override { if(i) return E_INVALIDARG; return SHStrDupW(L"RCON recovery — starting automation desktop",value); }
    HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD,HBITMAP* p) override { *p=nullptr; return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD,BOOL*,PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD,DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD,PCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD,BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD,DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serial,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        Audit(L"serialization-requested"); *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED; ZeroMemory(serial,sizeof(*serial)); *text=nullptr; *icon=CPSI_NONE;
        if (!ready || GetTickCount64()>ticket.expires || !EmptyConsole(session)) { Clear(); return S_OK; }
        LSA_HANDLE lsa=nullptr; NTSTATUS status=LsaConnectUntrusted(&lsa);
        if (status) { Clear(); return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status)); }
        char package[]="Negotiate"; LSA_STRING name={9,10,package}; ULONG auth=0;
        status=LsaLookupAuthenticationPackage(lsa,&name,&auth); LsaDeregisterLogonProcess(lsa);
        if (status) { Clear(); return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status)); }
        DWORD size=sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)+static_cast<DWORD>((wcslen(ticket.domain)+wcslen(ticket.user)+wcslen(ticket.password))*sizeof(WCHAR));
        auto raw=static_cast<BYTE*>(CoTaskMemAlloc(size)); if(!raw) { Clear(); return E_OUTOFMEMORY; } ZeroMemory(raw,size);
        auto logon=reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(raw); logon->Logon.MessageType=KerbInteractiveLogon;
        DWORD offset=sizeof(*logon);
        auto pack=[&](UNICODE_STRING& dest,const WCHAR* source) { dest.Length=dest.MaximumLength=static_cast<USHORT>(wcslen(source)*sizeof(WCHAR)); CopyMemory(raw+offset,source,dest.Length); dest.Buffer=reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset)); offset+=dest.Length; };
        pack(logon->Logon.LogonDomainName,ticket.domain); pack(logon->Logon.UserName,ticket.user); pack(logon->Logon.Password,ticket.password);
        Clear(); serial->ulAuthenticationPackage=auth; serial->clsidCredentialProvider=ProviderID; serial->cbSerialization=size; serial->rgbSerialization=raw;
        *response=CPGSR_RETURN_CREDENTIAL_FINISHED; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS status,NTSTATUS substatus,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override { Audit(L"logon-result",static_cast<HRESULT>(status)); Audit(L"logon-substatus",static_cast<HRESULT>(substatus)); Clear(); *text=nullptr; *icon=CPSI_NONE; return S_OK; }
};

class Factory final : public IClassFactory {
    LONG refs=1;
public:
    Factory(){ InterlockedIncrement(&objects); } ~Factory(){ InterlockedDecrement(&objects); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override { *out=nullptr; if(iid!=IID_IUnknown && iid!=IID_IClassFactory) return E_NOINTERFACE; *out=this; AddRef(); return S_OK; }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override { LONG r=InterlockedDecrement(&refs); if(!r) delete this; return r; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,REFIID iid,void** out) override { if(outer) return CLASS_E_NOAGGREGATION; auto p=new(std::nothrow) Provider; if(!p) return E_OUTOFMEMORY; HRESULT hr=p->QueryInterface(iid,out); p->Release(); return hr; }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override { if(lock) InterlockedIncrement(&objects); else InterlockedDecrement(&objects); return S_OK; }
};
extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID clsid,REFIID iid,void** out) { *out=nullptr; if(clsid!=ProviderID) return CLASS_E_CLASSNOTAVAILABLE; auto p=new(std::nothrow) Factory; if(!p) return E_OUTOFMEMORY; HRESULT hr=p->QueryInterface(iid,out); p->Release(); return hr; }
extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow() { return objects==0 ? S_OK : S_FALSE; }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID) { if(reason==DLL_PROCESS_ATTACH) { module=instance; DisableThreadLibraryCalls(instance); } return TRUE; }
