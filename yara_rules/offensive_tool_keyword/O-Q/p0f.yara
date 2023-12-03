rule p0f
{
    meta:
        description = "Detection patterns for the tool 'p0f' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0f"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string1 = /.{0,1000}\/tmp\/p0f\.log.{0,1000}/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string2 = /.{0,1000}install\sp0f.{0,1000}/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string3 = /.{0,1000}p0f\s\-i\seth.{0,1000}\s\-p.{0,1000}/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string4 = /.{0,1000}p0f\/p0f\.fp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
