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
        $string1 = /.{0,1000}\s\-t\sBindShell\s\-p\s.{0,1000}pwned\\pipe\\spoolss.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string2 = /.{0,1000}\s\-t\sCreateProcessAsUserW\s\-p\s.{0,1000}pwned\\pipe\\spoolss.{0,1000}\s\-e\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string3 = /.{0,1000}\/MultiPotato\.git.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string4 = /.{0,1000}\\\\\.\\pipe\\pwned\/pipe\/srvsvc.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string5 = /.{0,1000}61CE6716\-E619\-483C\-B535\-8694F7617548.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string6 = /.{0,1000}localhost\/pipe\/pwned.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string7 = /.{0,1000}MS\-RPRN\.exe\s\\\\.{0,1000}\s\\\\.{0,1000}\/pipe\/pwned.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string8 = /.{0,1000}MultiPotato\.cpp.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string9 = /.{0,1000}MultiPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string10 = /.{0,1000}MultiPotato\-main.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string11 = /.{0,1000}PetitPotamModified\.exe.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string12 = /.{0,1000}S3cretP4ssw0rd\!.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string13 = /.{0,1000}S3cur3Th1sSh1t\/MultiPotato.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string14 = /.{0,1000}TokenKidnapping\.cpp.{0,1000}/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string15 = /.{0,1000}TokenKidnapping\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
