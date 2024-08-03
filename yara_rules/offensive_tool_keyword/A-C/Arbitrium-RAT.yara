rule Arbitrium_RAT
{
    meta:
        description = "Detection patterns for the tool 'Arbitrium-RAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Arbitrium-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string1 = /\sa\s\-r\s\-cfg\s\-sfx\s\-z\"SFXAutoInstaller\.conf\"\sStandalone\.exe/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string2 = /\/Arbitrium\-RAT\.git/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string3 = /\[\+\]\sthe\sArbitrium\-Server\sis\srunning/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string4 = /2437b5db59dd1b987232c3f0b4ed53408bce886e98e879887d3a1c52ee93e141/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string5 = /2aa4f05b7acf28440538a3295d015e9dbbb919730d225e6b2f1051e328f6b3c4/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string6 = /3aafc3d5f312ebd5b34219e53e22592f82b039fffe70322982a03a498c604d3a/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string7 = /55bb7968642a55819b608e5e2e732982424b6f47e5ef774a0a35dff202f6321f/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string8 = /5cf784da346a55c15259f755ffc19790a90cd616449a47bb9617cf93bfe91441/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string9 = /78656dcbb5b795a7e71947b0f45fc054ced091ee2b62a41562879750ff111200/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string10 = /9eb78bef9bba6135087de0c8307c2f893eef9a4a2d1f8c37de643f059ce2f711/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string11 = /a976cdbaf7401fcf1de10254a4db2873b1b4c8c0b6f0e45a51978e3c77a6968a/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string12 = /c5ce3e817030e3bd925c09fcd3eaacf4705dfaacad9bdec485a4f246eb726a81/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string13 = /cmd\.exe\s\/c\s\"OK\!\"/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string14 = /d3eb242554adec76ed43cb76dae2c776bf086b2e2c15335c80fe79852286310e/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string15 = /e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string16 = /e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string17 = /http\:\/\/bit\.ly\/1qMn59d/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string18 = /im\-hanzou\/Arbitrium\-RAT/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string19 = /mimikatz\.py/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string20 = /New\-Object\sNet\.WebClient\)\.DownloadString.{0,1000}\s\-DumpCreds/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string21 = /pip\sinstall\sflask\sflask_cors\s\&\&\s\.\/runserver\.sh/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string22 = /Popen\(\"exec\s\$\(nc\s\-l\s0\.0\.0\.0\s\-p\s/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string23 = /python\sreverse_http\.py/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string24 = /User\-Agent\:\sJustKidding/ nocase ascii wide
        // Description: cross-platform fully undetectable remote access trojan to control Android Windows and Linux
        // Reference: https://github.com/im-hanzou/Arbitrium-RAT
        $string25 = /\'User\-Agent\'\:\s\'JustKidding\'/ nocase ascii wide

    condition:
        any of them
}
