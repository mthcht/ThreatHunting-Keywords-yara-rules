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
        $string1 = /.{0,1000}\s\-Type\sSMBClient\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string2 = /.{0,1000}\s\-Type\sSMBEnum\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string3 = /.{0,1000}\s\-Type\sSMBExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string4 = /.{0,1000}\s\-Type\sWMIExec\s\-Target\s.{0,1000}\s\-TargetExclude\s.{0,1000}\s\-Username\s.{0,1000}\s\-Hash\s.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string5 = /.{0,1000}Invoke\-TheHash.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string6 = /.{0,1000}Invoke\-TheHash\.ps1.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string7 = /.{0,1000}Invoke\-TheHash\.psd1.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string8 = /.{0,1000}Invoke\-TheHash\.psm1.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string9 = /.{0,1000}Invoke\-WMIExec\s.{0,1000}/ nocase ascii wide
        // Description: Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        // Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
        $string10 = /.{0,1000}Invoke\-WMIExec\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
