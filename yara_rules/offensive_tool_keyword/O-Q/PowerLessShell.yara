rule PowerLessShell
{
    meta:
        description = "Detection patterns for the tool 'PowerLessShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerLessShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. You can also execute raw shellcode using the same approach.
        // Reference: https://github.com/Mr-Un1k0d3r/PowerLessShell
        $string1 = /.{0,1000}malicious\.csproj.{0,1000}/ nocase ascii wide
        // Description: PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. You can also execute raw shellcode using the same approach.
        // Reference: https://github.com/Mr-Un1k0d3r/PowerLessShell
        $string2 = /.{0,1000}PowerLessShell.{0,1000}/ nocase ascii wide
        // Description: PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. You can also execute raw shellcode using the same approach.
        // Reference: https://github.com/Mr-Un1k0d3r/PowerLessShell
        $string3 = /.{0,1000}PowerLessShell\.py.{0,1000}/ nocase ascii wide
        // Description: PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. You can also execute raw shellcode using the same approach.
        // Reference: https://github.com/Mr-Un1k0d3r/PowerLessShell
        $string4 = /.{0,1000}shellcode_inject\.csproj.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
