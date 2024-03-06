rule Invoke_TheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string1 = /\s\-Type\sSMBClient\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string2 = /\s\-Type\sSMBEnum\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string3 = /\s\-Type\sSMBExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string4 = /\s\-Type\sWMIExec\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string5 = /\s\-Type\sWMIExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string6 = /\[\-\]\s.{0,1000}\sdoes\snot\shave\sService\sControl\sManager\swrite\sprivilege\son\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string7 = /\[\-\]\sInveigh\sRelay\ssession\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string8 = /Invoke\-SMBClient\.ps1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string9 = /Invoke\-SMBEnum/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string10 = /Invoke\-SMBExec/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string11 = /Invoke\-TheHash/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string12 = /Invoke\-TheHash\.ps1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string13 = /Invoke\-TheHash\.psd1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string14 = /Invoke\-TheHash\.psm1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string15 = /Invoke\-WMIExec\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string16 = /Invoke\-WMIExec\.ps1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string17 = /New\-PacketSMB2IoctlRequest/ nocase ascii wide

    condition:
        any of them
}
