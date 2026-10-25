#include "../SDK/RegistryGuard.h"
#include <iostream>
int wmain(int count,wchar_t** args){
 try{
  std::cout<<"Deny supported writes under one application registry branch until Enter is pressed.\n";
  if(count!=2){std::cout<<"Usage: RegistryGuardExample.exe \"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Product\"\n";return 0;}
  RegistryGuard::Session session;
  session.Start({RegistryGuard::Rule(1,args[1],RegistryGuard::Action::Deny)});
  std::cout<<"Policy active. Test a write from another application, then press Enter.\n";std::cin.get();
  auto batch=session.Read();
  for(unsigned i=0;i<batch.Count;++i)std::cout<<RegistryGuard::Utf8(RegistryGuard::Path(batch.Events[i]))<<" : "<<(batch.Events[i].Decision?"denied":"observed")<<'\n';
  // The session destructor closes its handle and removes its rules automatically.
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}return 0;
}
