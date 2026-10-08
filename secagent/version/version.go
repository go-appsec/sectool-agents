package version

import "runtime/debug"

// Version is injected via ldflags, else the module version from build info, else dev.
var Version = "dev"

func init() {
	Version = resolveVersion(Version, readBuildInfo())
}

func readBuildInfo() *debug.BuildInfo {
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi
	}
	return nil
}

// resolveVersion returns injected when set, else the module version, else dev.
func resolveVersion(injected string, bi *debug.BuildInfo) string {
	if injected != "dev" {
		return injected
	} else if bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
