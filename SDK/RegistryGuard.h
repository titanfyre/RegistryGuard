#pragma once
#include <string.h>
typedef unsigned long RG_U32;
typedef unsigned __int64 RG_U64;
typedef unsigned short RG_U16;
#define RG_VERSION 1u
#define RG_PATH 512u
#define RG_RULES 16u
#define RG_RING 256u
#define RG_READ 16u
#define RG_AUDIT 0u
#define RG_DENY 1u
#define RG_UNKNOWN_NAME 1u
#define RG_TRUNCATED 2u
#define RG_PRIOR_FAILURE 4u
#define RG_IOCTL(n) ((0x8000u<<16)|(3u<<14)|((n)<<2))
#define RG_SET RG_IOCTL(0x810u)
#define RG_STOP RG_IOCTL(0x811u)
#define RG_STATUS RG_IOCTL(0x812u)
#define RG_RECEIVE RG_IOCTL(0x813u)
typedef struct RG_RULE { RG_U32 Id,Action,Chars,Reserved; RG_U16 Path[RG_PATH]; } RG_RULE;
typedef struct RG_POLICY { RG_U32 Version,Size,Count,Reserved; RG_RULE Rules[RG_RULES]; } RG_POLICY;
typedef struct RG_REQUEST { RG_U32 Version,Size,Reserved[2]; } RG_REQUEST;
typedef struct RG_STATS {
 RG_U32 Version,Size,Active,RuleCount;
 RG_U64 Generation,Frequency,Produced,Denied,Dropped,UnknownNames;
 RG_U32 Available,Capacity,Reserved[2];
} RG_STATS;
typedef struct RG_EVENT {
 RG_U64 Sequence,Qpc,ProcessKey,Generation;
 RG_U32 ProcessId,ParentId,Operation,RuleId,Decision,Flags,Status,Chars;
 RG_U16 Path[RG_PATH];
} RG_EVENT;
typedef struct RG_BATCH { RG_STATS Stats; RG_U32 Count,Reserved[3]; RG_EVENT Events[RG_READ]; } RG_BATCH;
static __inline int RG_Text(const RG_U16* s,RG_U32 n) {
 RG_U32 i;
 if(!n||n>=RG_PATH||s[n])return 0;
 for(i=0;i<n;++i){
  if(s[i]<32||s[i]=='*'||s[i]=='?'||s[i]=='/'||(!s[i]))return 0;
  if(s[i]>=0xD800&&s[i]<=0xDBFF){if(++i>=n||s[i]<0xDC00||s[i]>0xDFFF)return 0;}
  else if(s[i]>=0xDC00&&s[i]<=0xDFFF)return 0;
 }
 for(i=n+1;i<RG_PATH;++i)if(s[i])return 0;
 return s[n-1]!='\\';
}
static __inline int RG_ValidPolicy(const RG_POLICY* p) {
 RG_U32 i,j;
 if(p->Version!=RG_VERSION||p->Size!=sizeof(*p)||p->Reserved||p->Count>RG_RULES)return 0;
 for(i=0;i<p->Count;++i){const RG_RULE* r=&p->Rules[i];
  if(!r->Id||r->Action>RG_DENY||r->Reserved||!RG_Text(r->Path,r->Chars)||r->Path[0]!='\\')return 0;
  for(j=0;j<i;++j)if(p->Rules[j].Id==r->Id)return 0;
 }
 for(i=p->Count;i<RG_RULES;++i){const unsigned char* bytes=(const unsigned char*)&p->Rules[i];for(j=0;j<sizeof(RG_RULE);++j)if(bytes[j])return 0;}
 return 1;
}
#ifndef _KERNEL_MODE
#include <windows.h>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
static_assert(sizeof(RG_RULE)==1040&&sizeof(RG_POLICY)==16656&&sizeof(RG_STATS)==80&&sizeof(RG_EVENT)==1088&&sizeof(RG_BATCH)==17504,"Unexpected wire packing");
namespace RegistryGuard {
enum class Action:unsigned { Audit=RG_AUDIT,Deny=RG_DENY };
RG_RULE Rule(unsigned id,const std::wstring& path,Action action=Action::Audit);
bool Valid(const RG_POLICY&) noexcept;
bool Valid(const RG_STATS&) noexcept;
bool Valid(const RG_BATCH&) noexcept;
std::wstring Path(const RG_EVENT&);
std::string Utf8(const std::wstring&);
class Session {
 struct State;std::unique_ptr<State> state_;
 void Command(unsigned,const void*,DWORD,void*,DWORD);
public:
 Session();~Session();
 Session(const Session&)=delete;Session& operator=(const Session&)=delete;
 void Start(const std::vector<RG_RULE>& rules={});
 void SetRules(const std::vector<RG_RULE>&);
 RG_BATCH Read(); // Immediate bounded drain; no polling or waits inside the driver.
 RG_STATS Status();
 void Stop() noexcept; // Closing the device also clears the policy.
};
}
#endif
