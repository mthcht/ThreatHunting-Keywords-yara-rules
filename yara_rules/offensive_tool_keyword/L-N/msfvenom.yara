rule msfvenom
{
    meta:
        description = "Detection patterns for the tool 'msfvenom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfvenom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string1 = " windows/shell/bind_tcp " nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string2 = "/msfvenom/" nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string3 = /exec\sCMD\=\/bin\/sh\s\-f\self\s\-o\s.{0,1000}\.elf/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string4 = "msfencode" nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string5 = "msfpayload" nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string6 = "msfvenom -" nocase ascii wide

    condition:
        any of them
}
