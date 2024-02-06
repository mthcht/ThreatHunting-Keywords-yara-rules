rule CoercedPotatoRDLL
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotatoRDLL' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotatoRDLL"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string1 = /\sCoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string2 = /\sspawn\sC\:\\Windows\\Temp\\beacon\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string3 = /\sspawn\sC\:\\Windows\\Temp\\loader\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string4 = /\/CoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string5 = /\/CoercedPotatoRDLL\.git/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string6 = /\[\+\]\sExploit\sworked.{0,1000}\sit\sshould\sexecute\syour\scommand\sas\sSYSTEM\!/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string7 = /\\\\\.\\pipe\\coerced\\pipe\\spoolss/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string8 = /\\127\.0\.0\.1\/pipe\/coerced/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string9 = /\\CoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string10 = /337ED7BE\-969A\-40C4\-A356\-BE99561F4633/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string11 = /CoercedPotato\sspawn\s/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string12 = /CoercedPotato\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string13 = /CoercedPotatoRDLL\-main/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string14 = /CoercePotato\scoerce/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string15 = /dist\/coercedpotato\.cna/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string16 = /ReflectiveDLLInjection\.h/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string17 = /ReflectiveLoader\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string18 = /sokaRepo\/CoercedPotatoRDLL/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string19 = /Spawn\sCoercedPotato\sas\sa\sReflective\sDLL/ nocase ascii wide

    condition:
        any of them
}
