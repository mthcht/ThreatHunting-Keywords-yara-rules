rule p0wnedShell
{
    meta:
        description = "Detection patterns for the tool 'p0wnedShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0wnedShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It has a lot of offensive PowerShell modules and binaries included to make the process of Post Exploitation easier. What we tried was to build an ?all in one? Post Exploitation tool which we could use to bypass all mitigations solutions (or at least some off). and that has all relevant tooling included. You can use it to perform modern attacks within Active Directory environments and create awareness within your Blue team so they can build the right defense strategies.
        // Reference: https://github.com/Cn33liz/p0wnedShell
        $string1 = /p0wnedShell/ nocase ascii wide

    condition:
        any of them
}
