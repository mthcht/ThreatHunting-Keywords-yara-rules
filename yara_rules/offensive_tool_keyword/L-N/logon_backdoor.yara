rule logon_backdoor
{
    meta:
        description = "Detection patterns for the tool 'logon_backdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logon_backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string1 = /\/backdoor\.bat/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string2 = /\/backdoor\.exe/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string3 = /\/logon_backdoor\.git/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string4 = /\[\sbackdoor\s\-\sDebug\s\]/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string5 = /\\backdoor\.bat/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string6 = /\\backdoor\.exe/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string7 = /\\backdoor\\backdoor\.mk/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string8 = /\\backdoor\\backdoor\.project/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string9 = /\\backdoor_new\.bat/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string10 = /\\logon_backdoor\\/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string11 = /\\logon_backdoor\-master/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string12 = /\\oem\\Desktop\\backdoor/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string13 = /\'1\.\sSet\sthe\sbackdoor\'/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string14 = /59a64374f430585117c385edce4ac8ff536cb2710a0037384f9f869601752af1/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string15 = /6e0055eba5cf62d9ac7b129e55d3f230fef2dd432d88313ae08d85d9ff5c2329/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string16 = /a93f02549ee6f5a59d0472755b8719284f64e0ac451906a42d8eb9f5738add67/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string17 = /Backdoor\shas\sbeen\sset\sup\ssuccessfully/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string18 = /Backdoor\sis\salready\sremoved\s\:\)/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string19 = /Backdoor\sis\salready\sset\sup\s\;\)/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string20 = /REG\sDELETE\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\"/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string21 = /szymon1118\/logon_backdoor/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/szymon1118/logon_backdoor
        $string22 = /title\slogon\sbackdoor/ nocase ascii wide

    condition:
        any of them
}
