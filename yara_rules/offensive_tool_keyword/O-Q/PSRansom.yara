rule PSRansom
{
    meta:
        description = "Detection patterns for the tool 'PSRansom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRansom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string1 = /\/PSRansom\s\-/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string2 = /\\PSRansom\s\-/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string3 = /C2Server\.ps1/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string4 = /JoelGMSec\/PSRansom/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string5 = /PSRansom\.ps1/ nocase ascii wide

    condition:
        any of them
}
