#include "RegistryGuardJsonSDK.h"
#include <string.h>
int main(void){uint64_t session=0;if(registryguard_json_open(&session))return 1;char *reply=registryguard_json_call(session,"{",1);if(!reply){registryguard_json_close(session);return 2;}int failed=strstr(reply,"\"ok\":false")==0;registryguard_json_free(reply);if(registryguard_json_close(session))return 3;return failed;}
