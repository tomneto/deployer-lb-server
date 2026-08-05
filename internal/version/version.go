// Package version carries the build-time version stamp shared by both
// binaries. Deliberately free of build tags and non-stdlib imports so it
// compiles in the `agent` and `lb` dependency graphs alike (D5).
package version

// Version is stamped at build time via
//
//	-ldflags "-X github.com/tomneto/deployer-lb-server/internal/version.Version=$(git describe --tags --always --dirty)"
//
// (see setup.sh download_or_build_binary). "dev" means an unstamped build.
var Version = "dev"
