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
        $string1 = /.{0,1000}\swindows\/shell\/bind_tcp\s.{0,1000}/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string2 = /.{0,1000}\/msfvenom\/.{0,1000}/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string3 = /.{0,1000}exec\sCMD\=\/bin\/sh\s\-f\self\s\-o\s.{0,1000}\.elf.{0,1000}/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string4 = /.{0,1000}msfencode.{0,1000}/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string5 = /.{0,1000}msfpayload.{0,1000}/ nocase ascii wide
        // Description: Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.
        // Reference: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
        $string6 = /.{0,1000}msfvenom\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
