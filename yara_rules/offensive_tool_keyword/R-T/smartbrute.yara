rule smartbrute
{
    meta:
        description = "Detection patterns for the tool 'smartbrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smartbrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string1 = " --bf-hashes-file " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string2 = " --bf-passwords-file " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string3 = " --ccache-ticket " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string4 = " --neo4j-host " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string5 = " -neo4j-password " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string6 = " --neo4j-port " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string7 = " --neo4j-user " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string8 = /\/smartbrute\.git/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string9 = "/smartbrute-main" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string10 = /\[bruteforce_mode\]/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string11 = /\\smartbrute\\/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string12 = /\\smartbrute\-main/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string13 = "52b07bced660711b3aa82b4cbf40156689045bcd695df40b1376c76e172beb8d" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string14 = /Bad\spassword\scounts\sdont\sreplicate\sbetween\sdomain\scontrollers\.\sOnly\sthe\sPDC\sknows\sthe\sreal\samount\sof\sthose\.\sBe\ssure\sto\starget\sthe\sPDC\sso\sthat\saccounts\sdon\'t\sget\slocked\sout/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string15 = /bruteforce_attack\(/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string16 = "bruteforce_mode_kerberos_mode" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string17 = "bruteforce_mode_ntlm_mode" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string18 = /bruteforce_try_password_or_hash\(/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string19 = /bruteforce_try_user\(/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string20 = /docstring\sfor\sbruteforce\./ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string21 = "Fetching domain information through a Kerberos auth over LDAP" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string22 = "Fetching domain information through NTLM over LDAP" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string23 = /options\.bruteforced_protocol/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string24 = "ShutdownRepo/smartbrute" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string25 = /smart_try_password_or_hash\(/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string26 = "smartbrute%2520brute" nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string27 = /smartbrute\.py/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string28 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string29 = "Starting bruteforce attack on " nocase ascii wide
        // Description: Password spraying and bruteforcing tool for Active Directory Domain Services
        // Reference: https://github.com/ShutdownRepo/smartbrute
        $string30 = "The smart password spraying and bruteforcing tool for Active Directory Domain Services" nocase ascii wide

    condition:
        any of them
}
