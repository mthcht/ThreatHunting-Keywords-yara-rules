rule conti
{
    meta:
        description = "Detection patterns for the tool 'conti' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conti"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string1 = /.{0,1000}\sC:\\ProgramData\\sh\.txt.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string2 = /.{0,1000}\sDriverName\s.{0,1000}Xeroxxx.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string3 = /.{0,1000}\/outfile:C:\\ProgramData\\hashes\.txt.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string4 = /.{0,1000}\\ProgramData\\asrephashes\.txt.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string5 = /.{0,1000}CVE\-2021\-34527\.ps1.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string6 = /.{0,1000}execute\-assembly\s.{0,1000}asreproast.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string7 = /.{0,1000}execute\-assembly\s.{0,1000}kerberoast.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string8 = /.{0,1000}HACKER.{0,1000}FUCKER.{0,1000}Xeroxxx.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string9 = /.{0,1000}Invoke\-Nightmare\s\-DLL\s.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string10 = /.{0,1000}Invoke\-Nightmare\s\-NewUser.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string11 = /.{0,1000}Invoke\-ShareFinder.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string12 = /.{0,1000}Invoke\-SMBAutoBrute.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string13 = /.{0,1000}ldapfilter:.{0,1000}admincount\=1.{0,1000}\s\/format:hashcat.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string14 = /.{0,1000}net\sdomain_controllers.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string15 = /.{0,1000}net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/dom.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string16 = /.{0,1000}net\sgroup\s\/\sdomain\s.{0,1000}Domain\sAdmins.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string17 = /.{0,1000}powershell\-import.{0,1000}Invoke\-Kerberoast\.ps1.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string18 = /.{0,1000}powershell\-import.{0,1000}ShareFinder\.ps1.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string19 = /.{0,1000}psinject\s.{0,1000}\sx64\sInvoke\-.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string20 = /.{0,1000}Set\-MpPreference\s\-DisableRealtimeMonitoring\s.{0,1000}true.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string21 = /.{0,1000}shell\snet\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string22 = /.{0,1000}shell\snet\slocalgroup\sadministrators.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string23 = /.{0,1000}shell\snltest\s\/dclist.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string24 = /.{0,1000}shell\srclone\.exe\scopy\s.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string25 = /.{0,1000}shell\swhoami.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string26 = /.{0,1000}spawnas\s.{0,1000}\s\\\sHACKER\shttps.{0,1000}/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string27 = /.{0,1000}start\sPsExec\.exe\s\-d\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
