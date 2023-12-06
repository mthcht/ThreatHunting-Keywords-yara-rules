rule PowershellKerberos
{
    meta:
        description = "Detection patterns for the tool 'PowershellKerberos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellKerberos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string1 = /\sdumper\.ps1/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string2 = /\/PowershellKerberos\.git/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string3 = /\\dumper\.ps1/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string4 = /\\injector\.ps1\s1\s/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string5 = /\\injector\.ps1\s2\s/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string6 = /\\PowershellKerberos/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string7 = /injector\.ps1.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string8 = /PowershellKerberos\-main/ nocase ascii wide

    condition:
        any of them
}
