rule JuicyPotato
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string1 = /\/JuicyPotato\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string2 = /\/JuicyPotato\.git/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string3 = /\/JuicyPotato_x32\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string4 = /\/JuicyPotato_x64\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string5 = "/JuicyPotato-webshell/" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string6 = /\\JuicyPotato\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = /\\JuicyPotato\.pdb/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string8 = /\\JuicyPotato\.pdb/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string9 = /\\JuicyPotato_x32\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string10 = /\\JuicyPotato_x64\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string11 = /\\JuicyPotato\-master/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string12 = /\\JuicyPotato\-shellcode\\/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string13 = /\]\sQueueUserAPC\sInject\sshellcode\scompleted\,\senjoy\!/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string14 = "0212bde3715a349a6b684dd54548638b5899be8d62a1e25559937e494e3cce54" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string15 = "02cbcc3c3b79a7f81165838af0605d7238e8c5ad7a6e2d59d7795c1f137fe7a4" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string16 = "050dcd051a109b6bd8804e769242ec4e1c087bdd2fb45880c2affeebb630cf77" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string17 = "1141183bf4a5fdb8a92a4bb9ae2278ec6391e1bc96ebee10245ad8a416372bd9" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string18 = "1141183bf4a5fdb8a92a4bb9ae2278ec6391e1bc96ebee10245ad8a416372bd9" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string19 = "146ca286f362290e96eda2a0b7cd9feb4e971763ba194731d1826e12e593439d" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string20 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string21 = "86b4924004cdef5e49cdc9ca7cbd2d8be156b8e8f41eceee92492cc315103eb8" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string22 = "f0761ad307781bdf8da94765abd1a2041ac12a52c7fdde85f00b2b2cab6d6ce8" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string23 = "f8c05d66a6fda535ef4e8e767c8e3ca5c93a0828ff03498b4b6cbe7e39bb617b" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string24 = "f8c05d66a6fda535ef4e8e767c8e3ca5c93a0828ff03498b4b6cbe7e39bb617b" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string25 = "fd0b9f09770685ed6f40ecabcd31bc467fa22801164b52fdc638334009b7c06f" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string26 = "JuicyPotato v%s" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string27 = /JuicyPotato\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string28 = "Modifying JuciyPotato by Uknow to support webshell" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string29 = /MSFRottenPotatoTestHarness\.exe/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string30 = "uknowsec/JuicyPotato" nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string31 = /x64\\Debug\\JuicyPotato/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/uknowsec/JuicyPotato
        $string32 = /x64\\Release\\JuicyPotato/ nocase ascii wide

    condition:
        any of them
}
