rule SharpDomainSpray
{
    meta:
        description = "Detection patterns for the tool 'SharpDomainSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDomainSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string1 = /.{0,1000}\/SharpDomainSpray\.git.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string2 = /.{0,1000}\/SharpSpray\.exe.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string3 = /.{0,1000}\\SharpDomainSpraty\\.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string4 = /.{0,1000}\\SharpSpray\.exe.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string5 = /.{0,1000}76FFA92B\-429B\-4865\-970D\-4E7678AC34EA.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string6 = /.{0,1000}HunnicCyber\/SharpDomainSpray.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string7 = /.{0,1000}Perform\spassword\sspraying\sfor\sall\sactive\susers\son\sa\sdomain.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string8 = /.{0,1000}SharpDomainSpray.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string9 = /.{0,1000}SharpDomainSpray\..{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string10 = /.{0,1000}SharpDomainSpray\-master.{0,1000}/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string11 = /.{0,1000}SharpSpray\.exe\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
