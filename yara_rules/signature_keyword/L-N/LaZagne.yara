rule LaZagne
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "signature_keyword"

    strings:
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string1 = /Hacktool\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string2 = "HTool-Lazagne" nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string3 = /Trojan\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string4 = /Win32\.LaZagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string5 = /Win64\.Lazagne/ nocase ascii wide

    condition:
        any of them
}
