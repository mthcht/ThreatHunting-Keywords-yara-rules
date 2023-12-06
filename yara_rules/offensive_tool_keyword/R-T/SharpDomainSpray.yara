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
        $string1 = /\/SharpDomainSpray\.git/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string2 = /\/SharpSpray\.exe/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string3 = /\\SharpDomainSpraty\\/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string4 = /\\SharpSpray\.exe/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string5 = /76FFA92B\-429B\-4865\-970D\-4E7678AC34EA/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string6 = /HunnicCyber\/SharpDomainSpray/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string7 = /Perform\spassword\sspraying\sfor\sall\sactive\susers\son\sa\sdomain/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string8 = /SharpDomainSpray/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string9 = /SharpDomainSpray\./ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string10 = /SharpDomainSpray\-master/ nocase ascii wide
        // Description: Basic password spraying tool for internal tests and red teaming
        // Reference: https://github.com/HunnicCyber/SharpDomainSpray
        $string11 = /SharpSpray\.exe\s/ nocase ascii wide

    condition:
        any of them
}
