rule NixImports
{
    meta:
        description = "Detection patterns for the tool 'NixImports' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NixImports"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string1 = /\/HInvoke\.cs/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string2 = /\\Loader\\Loader\.csproj/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string3 = /dr4k0nia\/NixImports/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string4 = /HInvokeHashGen\.cs/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string5 = /methodHash.{0,1000}528465795/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string6 = /NixImports\sby\sdr4k0nia/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string7 = /NixImports\.csproj/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string8 = /NixImports\.exe/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string9 = /NixImports\.git/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string10 = /NixImports\.sln/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string11 = /using\sNixImports/ nocase ascii wide

    condition:
        any of them
}
