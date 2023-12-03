rule Github__Username
{
    meta:
        description = "Detection patterns for the tool 'Github  Username' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github  Username"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github repo hosting exploitation tools for pentesters
        // Reference: https://github.com/SecureAuthCorp
        $string1 = /.{0,1000}\.com\/SecureAuthCorp.{0,1000}/ nocase ascii wide
        // Description: github repo hosting exploitation tools adn documentation for pentesters
        // Reference: https://github.com/SpiderLabs
        $string2 = /.{0,1000}\.com\/SpiderLabs.{0,1000}/ nocase ascii wide
        // Description: Github pentester username with lots of different exploitation tools
        // Reference: https://github.com/0x00-0x00
        $string3 = /.{0,1000}0x00\-0x00.{0,1000}/ nocase ascii wide
        // Description: github repo hosting exploitation tools for pentesters
        // Reference: https://github.com/RhinoSecurityLabs
        $string4 = /.{0,1000}RhinoSecurityLabs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
