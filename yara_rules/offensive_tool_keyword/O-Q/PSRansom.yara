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
        $string1 = /\sPopUpRansom/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string2 = /\/PSRansom\s\-/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string3 = /\\PSRansom\s\-/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string4 = /644e2fa03a4d45b8d0417819a7548339069df8d405131039006968b312c8c6f4/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string5 = /C2Server\sby\s\@JoelGMSec/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string6 = /C2Server\.ps1/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string7 = /cf78b329b4dcb1c211415309e2ddbf80833ad1669fd142a67c916aa6a8cecb88/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string8 = /JoelGMSec\/PSRansom/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string9 = /PSRansom\sby\s\@JoelGMSec/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string10 = /PSRansom\.ps1/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string11 = /pwd\/C2Files\// nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string12 = /pwd\\C2Files\\/ nocase ascii wide

    condition:
        any of them
}
