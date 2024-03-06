rule BeRoot
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string1 = /\sbeRoot\.exe/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string2 = /\sbeRoot\.py/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string3 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sGet\sSystem\sPriv\swith\sWebClient\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string4 = /\/beRoot\.exe/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string5 = /\/BeRoot\.git/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string6 = /\/beRoot\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string7 = /\/beRoot\.zip/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string8 = /\/BeRoot\/Linux\// nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string9 = /\/beroot\/modules\/.{0,1000}\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string10 = /\/gtfobins\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string11 = /\\beRoot\.exe/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string12 = /\\beRoot\.zip/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string13 = /\\beroot\\modules\\.{0,1000}\.py/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string14 = /\\DLL_Hijacking\./ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string15 = /52B0FF57\-7E0A\-4CA9\-84D4\-58DFA2456BA5/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string16 = /AlessandroZ\/BeRoot/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string17 = /beRoot\.exe\s\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string18 = /beroot\.py\s\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string19 = /BeRoot\-master/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string20 = /from\s\.modules\.exploit\simport\sExploit/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string21 = /from\s\.secretsdump\simport\sRemoteOperations/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string22 = /Getting\spermissions\sof\ssensitive\sfiles\./ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string23 = /import\scheck_currrent_user_privilege/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string24 = /import\scheck_sudoers_misconfigurations/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string25 = /linux\-exploit\-suggester/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string26 = /modules\.gtfobins\simport\sGTFOBins/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string27 = /modules\.interesting_files\simport\sInterestingFiles/ nocase ascii wide

    condition:
        any of them
}
