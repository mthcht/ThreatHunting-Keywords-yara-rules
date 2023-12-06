rule Priv2Admin
{
    meta:
        description = "Detection patterns for the tool 'Priv2Admin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Priv2Admin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.
        // Reference: https://github.com/gtworek/Priv2Admin
        $string1 = /\/NtQuerySystemInformation\.md/ nocase ascii wide
        // Description: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.
        // Reference: https://github.com/gtworek/Priv2Admin
        $string2 = /\/NtSetSystemInformation\.md/ nocase ascii wide
        // Description: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.
        // Reference: https://github.com/gtworek/Priv2Admin
        $string3 = /\/SeBackupPrivilege\.md/ nocase ascii wide
        // Description: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.
        // Reference: https://github.com/gtworek/Priv2Admin
        $string4 = /gtworek\/Priv2Admin/ nocase ascii wide

    condition:
        any of them
}
