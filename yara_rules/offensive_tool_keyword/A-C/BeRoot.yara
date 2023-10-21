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
        $string1 = /\sbeRoot\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string2 = /\/BeRoot\.git/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string3 = /\/beRoot\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string4 = /\/gtfobins\.py/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string5 = /AlessandroZ\/BeRoot/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string6 = /AlessandroZ\/BeRoot/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string7 = /BeRoot/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string8 = /beRoot\.exe/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string9 = /beroot\.py\s\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string10 = /beRoot\.zip/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string11 = /BeRoot\-master/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string12 = /linux\-exploit\-suggester/ nocase ascii wide

    condition:
        any of them
}