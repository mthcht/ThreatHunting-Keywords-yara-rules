rule masscan
{
    meta:
        description = "Detection patterns for the tool 'masscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "masscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string1 = /.{0,1000}\sinstall\s.{0,1000}masscan.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string2 = /.{0,1000}bin\/masscan.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string3 = /.{0,1000}masscan\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string4 = /.{0,1000}masscan\s\-\-nmap.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string5 = /.{0,1000}masscan\s\-p.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string6 = /.{0,1000}masscan.{0,1000}\s\s\-p.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string7 = /.{0,1000}robertdavidgraham\/masscan.{0,1000}/ nocase ascii wide
        // Description: TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // Reference: https://github.com/robertdavidgraham/masscan
        $string8 = /masscan\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
