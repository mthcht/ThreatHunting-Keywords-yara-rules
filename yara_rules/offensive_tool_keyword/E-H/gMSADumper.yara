rule gMSADumper
{
    meta:
        description = "Detection patterns for the tool 'gMSADumper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gMSADumper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string1 = /\s\-\-domain\s.{0,1000}\s\-\-kerberos/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string2 = /\/gMSADumper/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string3 = /gMSADumper\.py/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string4 = /micahvandeusen\/gMSADumper/ nocase ascii wide

    condition:
        any of them
}
