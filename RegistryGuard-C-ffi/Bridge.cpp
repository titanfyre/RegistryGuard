#include "SDK/RegistryGuard.h"
#include "WireTypes.h"
#include <map>
struct ProductSession{

std::unique_ptr<RegistryGuard::Session> session;
RegistryGuard::Session& Get(){if(!session)session=std::make_unique<RegistryGuard::Session>();return *session;}
std::vector<RG_RULE> Rules(const Json& a){auto array=a.at("rules");Require(array.is_array() && array.size()<=RG_RULES,"Too many rules");std::vector<RG_RULE> rules;for(const auto& r:array)rules.push_back(RegistryGuard::Rule(Number(r,"id"),Wide(r.at("path").get<std::string>()),static_cast<RegistryGuard::Action>(Number(r,"action",0,1))));return rules;}

Json Invoke(const std::string& op,const Json& a){

if(op=="check"){auto policy=FromWire<RG_POLICY>(a.at("policy"));return {{"valid",RegistryGuard::Valid(policy)},{"value",EncodeWire(policy)}};}
if(op=="make_rule")return EncodeWire(RegistryGuard::Rule(Number(a,"id"),Wide(a.at("path").get<std::string>()),static_cast<RegistryGuard::Action>(Number(a,"action",0,1))));
if(op=="start"){Get().Start(Rules(a));return Json::object();}
if(op=="set_rules"){Get().SetRules(Rules(a));return Json::object();}
if(op=="stop"){if(session)session->Stop();return Json::object();}
if(op=="status")return EncodeWire(Get().Status());
if(op=="read")return EncodeWire(Get().Read());
if(op=="event_path"){auto event=FromWire<RG_EVENT>(a.at("event"));Require(event.Chars<RG_PATH,"Event path exceeds capacity");return {{"path",Utf8(RegistryGuard::Path(event))}};}

throw SdkError(50,"Unknown operation");}
};
static Runtime<ProductSession> runtime;
extern "C" __declspec(dllexport) unsigned registryguard_json_open(std::uint64_t* id)noexcept{return runtime.Open(id);}
extern "C" __declspec(dllexport) unsigned registryguard_json_close(std::uint64_t id)noexcept{return runtime.Close(id);}
extern "C" __declspec(dllexport) char* registryguard_json_call(std::uint64_t id,const char* request,std::uint32_t length)noexcept{return runtime.Call(id,request,length);}
extern "C" __declspec(dllexport) void registryguard_json_free(char* response)noexcept{delete[] response;}
