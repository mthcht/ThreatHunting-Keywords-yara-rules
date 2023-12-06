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
        $string1 = /\/tmp\/p0f\.log/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string2 = /install\sp0f/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string3 = /p0f\s\-i\seth.{0,1000}\s\-p/ nocase ascii wide
        // Description: P0f is a tool that utilizes an array of sophisticated purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications
        // Reference: https://www.kali.org/tools/p0f/
        $string4 = /p0f\/p0f\.fp/ nocase ascii wide

    condition:
        any of them
}
