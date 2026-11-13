# RegistryGuard Dart / Flutter Windows SDK

`dart pub add registryguard` or `flutter pub add registryguard`.

```dart
final client=await Client.open(); // import package:registryguard/registryguard.dart
try { print(client.call("status")); } finally { client.close(); }
```

Windows x64 only. Calls are synchronous; use a worker isolate for UI responsiveness. For compiled Dart or Flutter Windows deployment, explicitly copy `lib/native/RegistryGuardJsonSDK.dll` beside the executable or pass its absolute libraryPath. This is an FFI package; automatic Flutter DLL bundling is not provided. A full Flutter application has not been compiled in this validation. [API](doc/API.md). Matching driver/license required separately.
