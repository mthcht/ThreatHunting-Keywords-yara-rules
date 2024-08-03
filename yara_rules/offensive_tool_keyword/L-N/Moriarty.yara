rule Moriarty
{
    meta:
        description = "Detection patterns for the tool 'Moriarty' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Moriarty"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string1 = /\.exe\s\-\-list\-vulns/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string2 = /\/Moriarty\.exe/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string3 = /\/Moriarty\.git/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string4 = /\\Moriarty\.exe/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string5 = /\]\sListing\sall\svulnerabilities\sscanned\sby\sMoriarty/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string6 = /\<Data\sName\=\"Product\"\>Moriarty\</ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string7 = /23bf773ba87ff687e14a90a2c0e552eb9b04abba32dcf81d9473f921dd44b99a/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string8 = /49AD5F38\-9E37\-4967\-9E84\-FE19C7434ED7/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string9 = /4c2a1547f0dab58a9db68d236d1a6aa817761b678c84b83f36d6dc31066d7cc3/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string10 = /5b9dfce5f5a8bb0e00e99a77f8c7197742651de267b0e9438d54d9ba9f1137b4/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string11 = /7c3c428effecb086e266482a9d18a622aa939ae380be734ab844c38aedc19a5d/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string12 = /9f3c1c73211ccb972f9d7e94a2130223cab43ffc7150ff432d1dafbb4a080eaf/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string13 = /b2c11ff250d4ece261e20ab73f7aeb22222698c365aa0752aa3d8a5785be8ed1/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string14 = /b8531483419f4819584b69edee3089b86bab98a1c39d3058074499d76939cff5/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string15 = /BC\-SECURITY\/Moriarty/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string16 = /ea5f032c532c30628da6fc76f5a4ad6ca4057ac2322f625b12fc907beadfc545/ nocase ascii wide
        // Description: Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // Reference: https://github.com/BC-SECURITY/Moriarty
        $string17 = /using\sMoriarty\.Msrc\;/ nocase ascii wide

    condition:
        any of them
}
