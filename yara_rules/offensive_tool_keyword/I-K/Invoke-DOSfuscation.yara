rule Invoke_DOSfuscation
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DOSfuscation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DOSfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-DOSfuscation is a PowerShell v2.0+ compatible cmd.exe command obfuscation framework. (White paper: https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
        // Reference: https://github.com/danielbohannon/Invoke-DOSfuscation
        $string1 = /Invoke\-DOSfuscation/ nocase ascii wide
        // Description: Revoke-Obfuscation is a PowerShell v3.0+ compatible PowerShell obfuscation detection framework. used for de obfuscating powershell scripts
        // Reference: https://github.com/danielbohannon/Revoke-Obfuscation
        $string2 = /Revoke\-Obfuscation/ nocase ascii wide

    condition:
        any of them
}
