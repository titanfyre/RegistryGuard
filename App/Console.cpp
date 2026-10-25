#include "../SDK/RegistryGuard.h"
#include <iostream>
int wmain(int count,wchar_t** args){
 try{
  std::cout<<"RegistryGuard - scoped native C++ policy SDK\n";
  if(count==2&&wcscmp(args[1],L"--status")==0){RegistryGuard::Session client;client.Start();auto s=client.Status();std::cout<<"Driver connected. Generation "<<s.Generation<<". No deny rules loaded.\n";return 0;}
  std::cout<<"Use the graphical app, or read Examples/policy.cpp for the smallest integration.\n"
           <<"The public preview does not install or enable an unsigned driver.\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
