rule pywsus
{
    meta:
        description = "Detection patterns for the tool 'pywsus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywsus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string1 = /\s\-c\s\'\/accepteula\s\/s\scalc\.exe\'\s\-e\sPsExec64\.exe/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string2 = /\/pywsus\.git/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string3 = /\/pywsus\-master\.zip/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string4 = /pywsus\.py/ nocase ascii wide

    condition:
        any of them
}
