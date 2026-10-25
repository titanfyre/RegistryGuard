#include "RegistryGuard.h"
#include <setupapi.h>
#include <algorithm>
#include <mutex>
namespace RegistryGuard {
namespace {
const GUID Interface={0x6cd00f54,0x5dee,0x46dc,{0x9d,0x53,0xa8,0x91,0x6d,0x1a,0x13,0x15}};
[[noreturn]] void Fail(DWORD code,const char* stage){
 wchar_t* text=nullptr;
 FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),reinterpret_cast<LPWSTR>(&text),0,nullptr);
 std::string message=text?Utf8(text):"Windows operation failed.";if(text)LocalFree(text);
 if(code==ERROR_NO_MORE_ITEMS||code==ERROR_FILE_NOT_FOUND)message="The signed RegistryGuard driver is not installed or running. See README installation steps.";
 if(code==ERROR_ACCESS_DENIED)message="Access denied. Run as administrator. The driver accepts only SYSTEM and administrators.";
 if(code==ERROR_SHARING_VIOLATION)message="Another RegistryGuard session already owns the device. Close that session first.";
 throw std::runtime_error(std::string(stage)+": "+message+" (Windows error "+std::to_string(code)+")");
}
HANDLE Open(){
 HDEVINFO set=SetupDiGetClassDevsW(&Interface,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
 if(set==INVALID_HANDLE_VALUE)Fail(GetLastError(),"Locate driver");
 struct Cleanup{HDEVINFO h;~Cleanup(){SetupDiDestroyDeviceInfoList(h);}} cleanup{set};
 SP_DEVICE_INTERFACE_DATA item{};item.cbSize=sizeof(item);
 if(!SetupDiEnumDeviceInterfaces(set,nullptr,&Interface,0,&item))Fail(GetLastError(),"Locate driver interface");
 DWORD size=0;SetupDiGetDeviceInterfaceDetailW(set,&item,nullptr,0,&size,nullptr);
 if(size<sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)||size>65536)Fail(ERROR_INVALID_DATA,"Interface length");
 std::vector<unsigned char> bytes(size);auto detail=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(bytes.data());detail->cbSize=sizeof(*detail);
 if(!SetupDiGetDeviceInterfaceDetailW(set,&item,detail,size,nullptr,nullptr))Fail(GetLastError(),"Read interface");
 HANDLE h=CreateFileW(detail->DevicePath,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(h==INVALID_HANDLE_VALUE)Fail(GetLastError(),"Open driver");return h;
}
}
std::string Utf8(const std::wstring& value){
 if(value.empty())return {};int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
 if(!n)throw std::invalid_argument("Invalid UTF-16 text.");std::string result(static_cast<size_t>(n),0);
 if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),result.data(),n,nullptr,nullptr))throw std::invalid_argument("Cannot encode UTF-16 text.");return result;
}
bool Valid(const RG_POLICY& p) noexcept{return RG_ValidPolicy(&p)!=0;}
bool Valid(const RG_STATS& s) noexcept{return s.Version==RG_VERSION&&s.Size==sizeof(s)&&s.Active<=1&&s.RuleCount<=RG_RULES&&s.Capacity==RG_RING&&s.Available<=RG_RING&&s.Frequency&&s.Denied<=s.Produced&&s.Dropped<=s.Produced&&s.UnknownNames<=s.Produced&&!s.Reserved[0]&&!s.Reserved[1];}
bool Valid(const RG_BATCH& b) noexcept{
 if(!Valid(b.Stats)||b.Count>RG_READ||b.Reserved[0]||b.Reserved[1]||b.Reserved[2])return false;
 RG_U64 last=0;
 for(RG_U32 i=0;i<b.Count;++i){const auto& e=b.Events[i];
  if(!e.Sequence||e.Sequence<=last||e.Sequence>b.Stats.Produced||!e.Generation||e.Generation>b.Stats.Generation||e.Chars>=RG_PATH||e.Path[e.Chars]||e.Decision>1||(e.Flags&~7u)||!e.Qpc||!e.ProcessKey||e.Operation<1||e.Operation>4)return false;
  if(e.Decision&&!e.RuleId)return false;last=e.Sequence;
 }return true;
}
RG_RULE Rule(unsigned id,const std::wstring& value,Action action){
 std::wstring path=value;
 if(path.rfind(L"\\REGISTRY\\",0)!=0)throw std::invalid_argument("Use a native registry path, such as \\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Product.");
 if(path.size()>=RG_PATH)throw std::invalid_argument("The native rule path is too long (maximum 511 UTF-16 units).");
 RG_RULE r{};r.Id=id;r.Action=static_cast<unsigned>(action);r.Chars=static_cast<unsigned>(path.size());std::copy(path.begin(),path.end(),r.Path);
 RG_POLICY p{};p.Version=RG_VERSION;p.Size=sizeof(p);p.Count=1;p.Rules[0]=r;
 if(!Valid(p))throw std::invalid_argument("Invalid rule: use a nonzero ID, a supported action and a complete native path without wildcards.");return r;
}
std::wstring Path(const RG_EVENT& e){if(e.Chars>=RG_PATH||e.Path[e.Chars])throw std::invalid_argument("Malformed event path.");return std::wstring(e.Path,e.Path+e.Chars);}
struct Session::State{HANDLE device=INVALID_HANDLE_VALUE;std::mutex lock;};
Session::Session():state_(std::make_unique<State>()){}
Session::~Session(){Stop();}
void Session::Command(unsigned code,const void* input,DWORD size,void* output,DWORD capacity){
 DWORD got=0;
 if(!DeviceIoControl(state_->device,code,const_cast<void*>(input),size,output,capacity,&got,nullptr))Fail(GetLastError(),"RegistryGuard request");
 if(got!=capacity)Fail(ERROR_INVALID_DATA,"RegistryGuard response length");
}
void Session::Start(const std::vector<RG_RULE>& rules){
 std::lock_guard<std::mutex> lock(state_->lock);
 if(state_->device!=INVALID_HANDLE_VALUE)throw std::runtime_error("Session is already started.");
 RG_POLICY p{};p.Version=RG_VERSION;p.Size=sizeof(p);p.Count=static_cast<unsigned>(rules.size());if(rules.size()>RG_RULES)throw std::invalid_argument("At most 16 rules are supported.");std::copy(rules.begin(),rules.end(),p.Rules);
 if(!Valid(p))throw std::invalid_argument("Invalid rule table.");
 state_->device=Open();try{Command(RG_SET,&p,sizeof(p),nullptr,0);}catch(...){CloseHandle(state_->device);state_->device=INVALID_HANDLE_VALUE;throw;}
}
void Session::SetRules(const std::vector<RG_RULE>& rules){
 std::lock_guard<std::mutex> lock(state_->lock);RG_POLICY p{};p.Version=RG_VERSION;p.Size=sizeof(p);if(rules.size()>RG_RULES)throw std::invalid_argument("At most 16 rules are supported.");p.Count=static_cast<unsigned>(rules.size());std::copy(rules.begin(),rules.end(),p.Rules);
 if(!Valid(p))throw std::invalid_argument("Invalid rule table.");Command(RG_SET,&p,sizeof(p),nullptr,0);
}
RG_STATS Session::Status(){std::lock_guard<std::mutex> lock(state_->lock);RG_REQUEST r{RG_VERSION,sizeof(r),{0,0}};RG_STATS s{};Command(RG_STATUS,&r,sizeof(r),&s,sizeof(s));if(!Valid(s))Fail(ERROR_INVALID_DATA,"Status validation");return s;}
RG_BATCH Session::Read(){std::lock_guard<std::mutex> lock(state_->lock);RG_REQUEST r{RG_VERSION,sizeof(r),{0,0}};RG_BATCH b{};Command(RG_RECEIVE,&r,sizeof(r),&b,sizeof(b));if(!Valid(b))Fail(ERROR_INVALID_DATA,"Batch validation");return b;}
void Session::Stop() noexcept{std::lock_guard<std::mutex> lock(state_->lock);if(state_->device!=INVALID_HANDLE_VALUE){CloseHandle(state_->device);state_->device=INVALID_HANDLE_VALUE;}}
}
