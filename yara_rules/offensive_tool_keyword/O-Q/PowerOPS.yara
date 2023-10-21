rule PowerOPS
{
    meta:
        description = "Detection patterns for the tool 'PowerOPS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerOPS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerOPS is an application written in C# that does not rely on powershell.exe but runs PowerShell commands and functions within a powershell runspace environment (.NET). It intends to include multiple offensive PowerShell modules to make the process of Post Exploitation easier.
        // Reference: https://github.com/fdiskyou/PowerOPS
        $string1 = /PowerOPS/ nocase ascii wide

    condition:
        any of them
}