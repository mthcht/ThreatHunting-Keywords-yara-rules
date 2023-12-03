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
        $string1 = /.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-kerberos.{0,1000}/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string2 = /.{0,1000}\/gMSADumper.{0,1000}/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string3 = /.{0,1000}gMSADumper\.py.{0,1000}/ nocase ascii wide
        // Description: Lists who can read any gMSA password blobs and parses them if the current user has access.
        // Reference: https://github.com/micahvandeusen/gMSADumper
        $string4 = /.{0,1000}micahvandeusen\/gMSADumper.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
