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
        $string1 = /\sinstall\sholehe/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string2 = /\/holehe\.git/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string3 = /from\sholehe\.core\simport/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string4 = /holehe\s.{0,1000}\@gmail\.com/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string5 = /holehe\.core\:main/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string6 = /holehe\\holehe/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string7 = /holehe\-master\./ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string8 = /megadose\/holehe/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string9 = /megadose\@protonmail\.com/ nocase ascii wide
        // Description: holehe allows you to check if the mail is used on different sites like twitter instagram and will retrieve information on sites with the forgotten password function.
        // Reference: https://github.com/megadose/holehe
        $string10 = /pornhub\.py/ nocase ascii wide

    condition:
        any of them
}
