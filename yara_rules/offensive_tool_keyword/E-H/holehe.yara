rule holehe
{
    meta:
        description = "Detection patterns for the tool 'holehe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "holehe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string1 = /.{0,1000}\sinstall\sholehe.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string2 = /.{0,1000}\/holehe\.git.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string3 = /.{0,1000}from\sholehe\.core\simport.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string4 = /.{0,1000}holehe\s.{0,1000}\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string5 = /.{0,1000}holehe\.core:main.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string6 = /.{0,1000}holehe\\holehe.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string7 = /.{0,1000}holehe\-master\..{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string8 = /.{0,1000}megadose\/holehe.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string9 = /.{0,1000}megadose\@protonmail\.com.{0,1000}/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string10 = /.{0,1000}pornhub\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
