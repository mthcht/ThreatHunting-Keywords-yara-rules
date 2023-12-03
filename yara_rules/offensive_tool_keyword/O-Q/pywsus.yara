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
        $string1 = /.{0,1000}\s\-c\s\'\/accepteula\s\/s\scalc\.exe\'\s\-e\sPsExec64\.exe.{0,1000}/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string2 = /.{0,1000}\/pywsus\.git.{0,1000}/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string3 = /.{0,1000}\/pywsus\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools such as Bettercap.
        // Reference: https://github.com/GoSecure/pywsus
        $string4 = /.{0,1000}pywsus\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
