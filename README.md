# Hyperscan.Dotnet

Dotnet experimental version of Intel's Hyperscan. Hyperscan is a software regular expression matching engine designed with high performance and flexibility in mind. It is implemented as a library that exposes a straightforward C API.

# Support
`netstandard2.0` `net461` `win-x64`

# Install NuGet
`Install-Package Hyperscan.Dotnet`

# Usage
Only supporting block mode db in current version.

```cs
using Hyperscan.Dotnet;

// initialize hs engine
Hyperscan hyperscanEngine = new Hyperscan();

// compile multi pattern database
hyperscanEngine.CompileBlockDatabase("path-to-pattern-file");

// scan any input
int matchedId = hyperscanEngine.ScanSingle("abc");

// dispose unmanaged resources
hyperscanEngine.Dispose();
```
