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
        $string1 = /.{0,1000}\sdumper\.ps1.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string2 = /.{0,1000}\/PowershellKerberos\.git.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string3 = /.{0,1000}\\dumper\.ps1.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string4 = /.{0,1000}\\injector\.ps1\s1\s.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string5 = /.{0,1000}\\injector\.ps1\s2\s.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string6 = /.{0,1000}\\PowershellKerberos.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string7 = /.{0,1000}injector\.ps1.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Some scripts to abuse kerberos using Powershell
        // Reference: https://github.com/MzHmO/PowershellKerberos
        $string8 = /.{0,1000}PowershellKerberos\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
