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
        $string1 = /\sC:\\ProgramData\\sh\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string2 = /\sDriverName\s.*Xeroxxx/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string3 = /\/outfile:C:\\ProgramData\\hashes\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string4 = /\\ProgramData\\asrephashes\.txt/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string5 = /CVE\-2021\-34527\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string6 = /execute\-assembly\s.*asreproast/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string7 = /execute\-assembly\s.*kerberoast/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string8 = /HACKER.*FUCKER.*Xeroxxx/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string9 = /Invoke\-Nightmare\s\-DLL\s/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string10 = /Invoke\-Nightmare\s\-NewUser/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string11 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string12 = /Invoke\-SMBAutoBrute/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string13 = /ldapfilter:.*admincount\=1.*\s\/format:hashcat/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string14 = /net\sdomain_controllers/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string15 = /net\sgroup\s.*Enterprise\sAdmins.*\s\/dom/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string16 = /net\sgroup\s\/\sdomain\s.*Domain\sAdmins/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string17 = /powershell\-import.*Invoke\-Kerberoast\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string18 = /powershell\-import.*ShareFinder\.ps1/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string19 = /psinject\s.*\sx64\sInvoke\-/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string20 = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s.*true/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string21 = /shell\snet\sgroup\s.*Domain\sComputers.*\s\/domain/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string22 = /shell\snet\slocalgroup\sadministrators/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string23 = /shell\snltest\s\/dclist/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string24 = /shell\srclone\.exe\scopy\s/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string25 = /shell\swhoami/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string26 = /spawnas\s.*\s\\\sHACKER\shttps/ nocase ascii wide
        // Description: Conti is a Ransomware-as-a-Service (RaaS) that was first observed in December 2019. Conti has been deployed via TrickBot and used against major corporations and government agencies particularly those in North America. As with other ransomware families - actors using Conti steal sensitive files and information from compromised networks and threaten to publish this data unless the ransom is paid
        // Reference: https://www.securonix.com/blog/on-conti-ransomware-tradecraft-detection/
        $string27 = /start\sPsExec\.exe\s\-d\s/ nocase ascii wide

    condition:
        any of them
}