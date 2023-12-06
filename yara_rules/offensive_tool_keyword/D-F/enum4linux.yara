rule enum4linux
{
    meta:
        description = "Detection patterns for the tool 'enum4linux' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "enum4linux"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe 
        // Reference: https://github.com/CiscoCXSecurity/enum4linux
        $string1 = /enum4linux/ nocase ascii wide

    condition:
        any of them
}
