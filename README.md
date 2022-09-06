# Hyperscan.Dotnet

A Fast Multi-pattern Regex Matcher.

[![NuGet version](https://badge.fury.io/nu/hyperscan.dotnet.svg)](https://badge.fury.io/nu/hyperscan.dotnet)

Dotnet experimental version of Intel's Hyperscan. Hyperscan is a software regular expression matching engine designed with high performance and flexibility in mind. It is implemented as a library that exposes a straightforward C API. 

**Library not fully supported - very limited.**

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

## Pattern File Format
Hyperscan.Dotnet expects to read and parse the regular expression pattern file with following format.

`<id>:/<regex>/<flags>`

1. `id`: the integer rule id
2. `regex`: the regex pattern (PCRE)
3. `flags`: flags which modify the behaviour of the expression. Multiple flags may be used (`i` caseless, `H` single match)

ex:
```
1:/[0-9]+/iH
2:/[a-z]+/iH
```
