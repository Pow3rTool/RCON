//go:build windows && recoveryprovider

package main

import _ "embed"

//go:embed windows/recovery/rcon-recovery.dll
var bundledRecoveryProvider []byte

func init() { recoveryProviderDLL = bundledRecoveryProvider }
