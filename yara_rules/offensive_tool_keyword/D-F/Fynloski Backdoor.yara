rule Fynloski_Backdoor
{
    meta:
        description = "Detection patterns for the tool 'Fynloski Backdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fynloski Backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string1 = "#BOT#CloseServer" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string2 = "#BOT#OpenUrl" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string3 = "#BOT#RunPrompt" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string4 = "#BOT#SvrUninstall" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string5 = "#BOT#URLDownload" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string6 = "#BOT#URLUpdate" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string7 = "#GetClipboardText" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string8 = "ActiveOfflineKeylogger" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string9 = "ActiveOnlineKeylogger" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string10 = "ActiveOnlineKeyStrokes" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string11 = "ACTIVEREMOTESHELL" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string12 = "DDOSHTTPFLOOD" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string13 = "DDOSSYNFLOOD" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string14 = "DDOSUDPFLOOD" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string15 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string16 = "KILLREMOTESHELL" nocase ascii wide
        // Description: Backdoor Fynloski also knownn as Darkcoment - allows attackers to control the infected system and install other malware remotely
        // Reference: https://www.hybrid-analysis.com/sample/43b40a12a966313f889c338e07239a42af67a69745507e45c4e899bcfa913b81/5a3d55d27ca3e1257f7044f3
        $string17 = /ping\s127\.0\.0\.1\s\-n\s4\s\>\sNUL\s\&\&\s\\"/ nocase ascii wide

    condition:
        any of them
}
