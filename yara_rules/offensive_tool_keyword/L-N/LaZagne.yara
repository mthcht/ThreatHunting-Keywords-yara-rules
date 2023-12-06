rule LaZagne
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string1 = /\slaZagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string2 = /\smemorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string3 = /\/creddump7.{0,1000}\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string4 = /\/laZagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string5 = /\/memorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string6 = /\/pswRecovery4Moz\.txt/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string7 = /AlessandroZ\/LaZagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string8 = /Application\.Lazagne\.H/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string9 = /Hacktool\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string10 = /HTool\-Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string11 = /laZagne\.exe\sbrowsers/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string12 = /Lazagne\.exe/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string13 = /Lazagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string14 = /LaZagne\-master\.zip/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string15 = /memory.{0,1000}mimipy\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string16 = /memory\/onepassword\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string17 = /memorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string18 = /mimipy\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string19 = /Trojan\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string20 = /Win32\.LaZagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string21 = /Win64\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string22 = /windows.{0,1000}lsa_secrets\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string23 = /Windows\/lazagne\.spec/ nocase ascii wide

    condition:
        any of them
}
