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
        $string1 = /.{0,1000}\slaZagne\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string2 = /.{0,1000}\smemorydump\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string3 = /.{0,1000}\/creddump7.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string4 = /.{0,1000}\/laZagne\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string5 = /.{0,1000}\/memorydump\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string6 = /.{0,1000}\/pswRecovery4Moz\.txt.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string7 = /.{0,1000}AlessandroZ\/LaZagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string8 = /.{0,1000}Application\.Lazagne\.H.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string9 = /.{0,1000}Hacktool\.Lazagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string10 = /.{0,1000}HTool\-Lazagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string11 = /.{0,1000}laZagne\.exe\sbrowsers.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string12 = /.{0,1000}Lazagne\.exe.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string13 = /.{0,1000}Lazagne\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string14 = /.{0,1000}LaZagne\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string15 = /.{0,1000}memory.{0,1000}mimipy\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string16 = /.{0,1000}memory\/onepassword\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string17 = /.{0,1000}memorydump\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string18 = /.{0,1000}mimipy\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string19 = /.{0,1000}Trojan\.Lazagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string20 = /.{0,1000}Win32\.LaZagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string21 = /.{0,1000}Win64\.Lazagne.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string22 = /.{0,1000}windows.{0,1000}lsa_secrets\.py.{0,1000}/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string23 = /.{0,1000}Windows\/lazagne\.spec.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
