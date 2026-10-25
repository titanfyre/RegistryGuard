#include "../SDK/RegistryGuard.h"
#include <iostream>
#include <random>
void Check(bool b){if(!b)throw std::runtime_error("Offline protocol check failed.");}
int main(){try{
 RG_POLICY p{};p.Version=RG_VERSION;p.Size=sizeof(p);Check(RegistryGuard::Valid(p));
 p.Count=1;p.Rules[0]=RegistryGuard::Rule(1,L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Product",RegistryGuard::Action::Deny);Check(RegistryGuard::Valid(p));
 auto base=p;p.Rules[0].Chars=RG_PATH;Check(!RegistryGuard::Valid(p));p=base;p.Rules[0].Path[10]=0;Check(!RegistryGuard::Valid(p));
 p=base;p.Count=2;p.Rules[1]=p.Rules[0];Check(!RegistryGuard::Valid(p));p=base;p.Rules[15].Reserved=1;Check(!RegistryGuard::Valid(p));
 p=base;p.Rules[0].Path[1]='*';Check(!RegistryGuard::Valid(p));p=base;p.Reserved=1;Check(!RegistryGuard::Valid(p));
 RG_STATS stats{};stats.Version=RG_VERSION;stats.Size=sizeof(stats);stats.Capacity=RG_RING;stats.Frequency=10000000;Check(RegistryGuard::Valid(stats));
 RG_BATCH b{};b.Stats=stats;Check(RegistryGuard::Valid(b));b.Count=RG_READ+1;Check(!RegistryGuard::Valid(b));
 std::mt19937 rng(7731);unsigned valid=0;for(unsigned i=0;i<1000000;++i){p=base;auto bytes=reinterpret_cast<unsigned char*>(&p);for(int j=0;j<3;++j)bytes[rng()%sizeof(p)]=static_cast<unsigned char>(rng());if(RegistryGuard::Valid(p))++valid;}
 bool missing=false;try{RegistryGuard::Session client;client.Status();}catch(const std::exception&){missing=true;}Check(missing);
 std::cout<<"Offline checks passed; one million malformed-policy mutations checked (accepted: "<<valid<<"). No driver loaded.\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
