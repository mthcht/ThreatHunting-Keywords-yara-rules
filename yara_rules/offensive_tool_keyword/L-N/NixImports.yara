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
        $string1 = /.{0,1000}\/HInvoke\.cs.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string2 = /.{0,1000}\\Loader\\Loader\.csproj.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string3 = /.{0,1000}dr4k0nia\/NixImports.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string4 = /.{0,1000}HInvokeHashGen\.cs.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string5 = /.{0,1000}methodHash.{0,1000}528465795.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string6 = /.{0,1000}NixImports\sby\sdr4k0nia.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string7 = /.{0,1000}NixImports\.csproj.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string8 = /.{0,1000}NixImports\.exe.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string9 = /.{0,1000}NixImports\.git.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string10 = /.{0,1000}NixImports\.sln.{0,1000}/ nocase ascii wide
        // Description: A .NET malware loader using API-Hashing to evade static analysis
        // Reference: https://github.com/dr4k0nia/NixImports
        $string11 = /.{0,1000}using\sNixImports.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
