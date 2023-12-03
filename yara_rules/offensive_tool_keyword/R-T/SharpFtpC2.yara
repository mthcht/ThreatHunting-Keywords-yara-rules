rule SharpFtpC2
{
    meta:
        description = "Detection patterns for the tool 'SharpFtpC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpFtpC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string1 = /.{0,1000}\/FtpC2\/.{0,1000}/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string2 = /.{0,1000}\\FtpC2\\.{0,1000}/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string3 = /.{0,1000}\\net.{0,1000}\\ftpagent\.exe.{0,1000}/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string4 = /.{0,1000}FtpC2\.exe.{0,1000}/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string5 = /.{0,1000}FtpC2\.Tasks.{0,1000}/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string6 = /.{0,1000}SharpFtpC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
