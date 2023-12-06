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
        $string1 = /\sinstall\sarmitage/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string2 = /\.\/teamserver\s/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string3 = /\/armitage\.git/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string4 = /\/passhash\.sl/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string5 = /armitage\.exe/ nocase ascii wide
        // Description: Armitage is a graphical cyber attack management tool for Metasploit that visualizes your targets. recommends exploits and exposes the advanced capabilities of the framework 
        // Reference: https://github.com/r00t0v3rr1d3/armitage
        $string6 = /meterpreter\.sl/ nocase ascii wide

    condition:
        any of them
}
