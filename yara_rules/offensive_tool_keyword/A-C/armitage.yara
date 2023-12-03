rule armitage
{
    meta:
        description = "Detection patterns for the tool 'armitage' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "armitage"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string1 = /.{0,1000}\sinstall\sarmitage.{0,1000}/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string2 = /.{0,1000}\.\/teamserver\s.{0,1000}/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string3 = /.{0,1000}\/armitage\.git.{0,1000}/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string4 = /.{0,1000}\/passhash\.sl.{0,1000}/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string5 = /.{0,1000}armitage\.exe.{0,1000}/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string6 = /.{0,1000}meterpreter\.sl.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
