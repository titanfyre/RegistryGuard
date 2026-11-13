# RegistryGuard PowerShell SDK

PowerShell7.4+ Windows x64. `Install-Module RegistryGuard -Scope CurrentUser`.

```powershell
$client=Connect-RegistryGuardSDK
try { Invoke-RegistryGuardSDK -Client $client -Operation status } finally { Disconnect-RegistryGuardSDK -Client $client }
```

Use -Arguments with a hashtable matching [schema](docs/API.md). Native errors retain their Windows code through the inner exception. Matching driver installed separately.
