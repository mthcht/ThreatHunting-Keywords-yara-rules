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
        $string1 = /.{0,1000}\sbeRoot\.py.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string2 = /.{0,1000}\/BeRoot\.git.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string3 = /.{0,1000}\/beRoot\.py.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string4 = /.{0,1000}\/gtfobins\.py.{0,1000}/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string5 = /.{0,1000}AlessandroZ\/BeRoot.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string6 = /.{0,1000}AlessandroZ\/BeRoot.{0,1000}/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string7 = /.{0,1000}BeRoot.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string8 = /.{0,1000}beRoot\.exe.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string9 = /.{0,1000}beroot\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string10 = /.{0,1000}beRoot\.zip.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string11 = /.{0,1000}BeRoot\-master.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string12 = /.{0,1000}linux\-exploit\-suggester.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
