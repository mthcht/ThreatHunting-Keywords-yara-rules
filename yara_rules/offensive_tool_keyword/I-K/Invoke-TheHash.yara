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
        $string1 = /\s\-Type\sSMBClient\s\-Target\s.*\s\-TargetExclude\s.*\s\-Username\s.*\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string2 = /\s\-Type\sSMBEnum\s\-Target\s.*\s\-TargetExclude\s.*\s\-Username\s.*\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string3 = /\s\-Type\sSMBExec\s\-Target\s.*\s\-TargetExclude\s.*\s\-Username\s.*\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string4 = /\s\-Type\sWMIExec\s\-Target\s.*\s\-TargetExclude\s.*\s\-Username\s.*\s\-Hash\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string5 = /Invoke\-TheHash/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string6 = /Invoke\-TheHash\.ps1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string7 = /Invoke\-TheHash\.psd1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string8 = /Invoke\-TheHash\.psm1/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string9 = /Invoke\-WMIExec\s/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string10 = /Invoke\-WMIExec\.ps1/ nocase ascii wide

    condition:
        any of them
}