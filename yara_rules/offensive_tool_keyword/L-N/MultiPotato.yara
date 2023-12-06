rule MultiPotato
{
    meta:
        description = "Detection patterns for the tool 'MultiPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MultiPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string1 = /\s\-t\sBindShell\s\-p\s.{0,1000}pwned\\pipe\\spoolss/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string2 = /\s\-t\sCreateProcessAsUserW\s\-p\s.{0,1000}pwned\\pipe\\spoolss.{0,1000}\s\-e\s.{0,1000}\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string3 = /\/MultiPotato\.git/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string4 = /\\\\\.\\pipe\\pwned\/pipe\/srvsvc/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string5 = /61CE6716\-E619\-483C\-B535\-8694F7617548/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string6 = /localhost\/pipe\/pwned/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string7 = /MS\-RPRN\.exe\s\\\\.{0,1000}\s\\\\.{0,1000}\/pipe\/pwned/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string8 = /MultiPotato\.cpp/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string9 = /MultiPotato\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string10 = /MultiPotato\-main/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string11 = /PetitPotamModified\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string12 = /S3cretP4ssw0rd\!/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string13 = /S3cur3Th1sSh1t\/MultiPotato/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string14 = /TokenKidnapping\.cpp/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string15 = /TokenKidnapping\.exe/ nocase ascii wide

    condition:
        any of them
}
