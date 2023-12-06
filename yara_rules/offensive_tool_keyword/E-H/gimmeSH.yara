rule gimmeSH
{
    meta:
        description = "Detection patterns for the tool 'gimmeSH' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmeSH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: gimmeSH. is a tool that generates a custom cheatsheet for Reverse Shell. File Transfer and Msfvenom within your terminal. you just need to provide the platform. your Internet protocol address and your port number.
        // Reference: https://github.com/A3h1nt/gimmeSH
        $string1 = /\.\/gimmeSH/ nocase ascii wide
        // Description: gimmeSH. is a tool that generates a custom cheatsheet for Reverse Shell. File Transfer and Msfvenom within your terminal. you just need to provide the platform. your Internet protocol address and your port number.
        // Reference: https://github.com/A3h1nt/gimmeSH
        $string2 = /\/gimmeSH\.sh/ nocase ascii wide
        // Description: gimmeSH. is a tool that generates a custom cheatsheet for Reverse Shell. File Transfer and Msfvenom within your terminal. you just need to provide the platform. your Internet protocol address and your port number.
        // Reference: https://github.com/A3h1nt/gimmeSH
        $string3 = /A3h1nt\/gimmeSH/ nocase ascii wide

    condition:
        any of them
}
