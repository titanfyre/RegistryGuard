#pragma once
// No allocation or registry/filesystem calls while holding the event/policy lock.
static __inline RG_U16 Upper(RG_U16 c){return (RG_U16)RtlUpcaseUnicodeChar((WCHAR)c);}
static __inline BOOLEAN Equal(const RG_U16* a,const RG_U16* b,RG_U32 n){RG_U32 i;for(i=0;i<n;++i)if(Upper(a[i])!=Upper(b[i]))return FALSE;return TRUE;}
static __inline BOOLEAN Match(const RG_RULE* r,const RG_U16* name,RG_U32 chars,BOOLEAN subtree){
 if(chars<r->Chars||(!subtree&&chars!=r->Chars))return FALSE;
 return Equal(r->Path,name,r->Chars)&&(chars==r->Chars||(subtree&&name[r->Chars]=='\\'));
}
static __inline BOOLEAN Ancestor(const RG_RULE* r,const RG_U16* name,RG_U32 chars){return chars<r->Chars&&r->Path[chars]=='\\'&&Equal(r->Path,name,chars);}
static __inline BOOLEAN Starts(const RG_RULE* r,const WCHAR* prefix){RG_U32 n=(RG_U32)wcslen(prefix);return r->Chars>n&&Equal(r->Path,(const RG_U16*)prefix,n);}
static __inline BOOLEAN AllowedScope(const RG_RULE* r){ return Starts(r,L"\\REGISTRY\\MACHINE\\SOFTWARE\\"); }
