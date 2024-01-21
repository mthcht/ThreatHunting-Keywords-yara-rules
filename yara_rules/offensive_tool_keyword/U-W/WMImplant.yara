rule WMImplant
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string1 = /\s\-Remote_Posh\s\-Location\s.{0,1000}\.ps1\s\-Function\sInvoke\-.{0,1000}\s\-ComputerName\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string2 = /Edit\-FileWMI/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string3 = /Find\-FileWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string4 = /Find\-VacantComputer/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string5 = /Get\-FileContentsWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string6 = /Get\-WMIEventLogins/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string7 = /Invoke\-FileTransferWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string8 = /Invoke\-LSWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string9 = /Invoke\-PowerOptionsWMI/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string10 = /Invoke\-ProcessPunisher/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string11 = /Invoke\-ProcSpawn\s\-Command\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string12 = /Invoke\-ProcSpawn/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string13 = /Invoke\-RemoteScriptWithOutput/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string14 = /Invoke\-WMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string15 = /Invoke\-WMIObfuscatedPSCommand/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string16 = /powershell\.exe\s\-command\s.{0,1000}Enable\-PSRemoting\s\-Force.{0,1000}\s\-ComputerName\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string17 = /Show\-WMImplantMainMenu/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string18 = /WMImplant/ nocase ascii wide

    condition:
        any of them
}
