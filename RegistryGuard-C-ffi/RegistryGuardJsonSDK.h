/* SPDX-License-Identifier: MIT */
#ifndef REGISTRYGUARD_CSDK_H
#define REGISTRYGUARD_CSDK_H
#include <stdint.h>
#if !defined(_WIN32) || !defined(_WIN64)
#error This SDK requires Windows x64.
#endif
#ifdef __cplusplus
#define REGISTRYGUARD_CSDK_NOEXCEPT noexcept
extern "C" {
#else
#define REGISTRYGUARD_CSDK_NOEXCEPT
#endif
#if defined(REGISTRYGUARD_CSDK_BUILD)
#define REGISTRYGUARD_CSDK_API __declspec(dllexport)
#else
#define REGISTRYGUARD_CSDK_API __declspec(dllimport)
#endif
/* open is inert. One active session per loaded product DLL.
   call accepts length-delimited UTF-8 JSON and returns an allocated UTF-8
   response, or NULL on allocation failure. Always free with this same DLL.
   Session/operation handles are scoped to the client that returned them. */
REGISTRYGUARD_CSDK_API uint32_t registryguard_json_open(uint64_t *session) REGISTRYGUARD_CSDK_NOEXCEPT;
REGISTRYGUARD_CSDK_API uint32_t registryguard_json_close(uint64_t session) REGISTRYGUARD_CSDK_NOEXCEPT;
REGISTRYGUARD_CSDK_API char *registryguard_json_call(uint64_t session,const char *request,uint32_t length) REGISTRYGUARD_CSDK_NOEXCEPT;
REGISTRYGUARD_CSDK_API void registryguard_json_free(char *response) REGISTRYGUARD_CSDK_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef REGISTRYGUARD_CSDK_NOEXCEPT
#endif
