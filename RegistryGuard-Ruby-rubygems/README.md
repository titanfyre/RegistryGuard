# RegistryGuard Ruby SDK

`gem install registryguard`

Windows x64 Ruby3.1+.

```ruby
require "registryguard"
RegistryGuardSDK::Client.open { |client| p client.call("status") }
```

[API and operation schema](docs/API.md). Matching driver installed separately.
