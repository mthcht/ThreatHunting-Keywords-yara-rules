rule Xrulez
{
    meta:
        description = "Detection patterns for the tool 'Xrulez' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xrulez"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string1 = /\sXRulez\.cpp/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string2 = /\/XRulez\sbinaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string3 = /\/XRulez\.exe/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string4 = /\/XRulez\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string5 = /\\2fac5c2a114c7896c33fb2b0a9f6443d\\/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string6 = /\\XRulez\.cpp/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string7 = /\\XRulez\.exe/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string8 = /\\XRulez\.sln/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string9 = /\\XRulez\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string10 = /\\XRulez\\Injector\\/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string11 = /070ccb075d1dada74121d232e657a9aeda429014f44da57491aa92fc5a279924/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string12 = /14083A04\-DD4B\-4E7D\-A16E\-86947D3D6D74/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string13 = /2661F29C\-69F5\-4010\-9198\-A418C061DD7C/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string14 = /578a42cf90cf1bcc569f925d7909bbedd2756367906d2875a23cbc8bb1628577/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string15 = /b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string16 = /b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string17 = /XRMod_h64e\.exe/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string18 = /Xrulez\s\+\sXRMod\.rwdi\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string19 = /Xrulez\s\+\sXRMod\.x64\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string20 = /Xrulez\s\+\sXRMod\.x86\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string21 = /XRulez\sbinaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string22 = /XRulez\.\%2B\.XRMod\.rwdi\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string23 = /XRulez\.\%2B\.XRMod\.x64\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string24 = /XRulez\.\%2B\.XRMod\.x86\.binaries\.zip/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string25 = /XRulez\.\+\.XRMod\.x64\.binaries/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string26 = /XRulez\.exe\s/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string27 = /XRulez_h64d\.dll/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string28 = /XRulez_h64e\.exe/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string29 = /XRulez_rwdi86d\.dll/ nocase ascii wide
        // Description: XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // Reference: https://github.com/FSecureLABS/Xrulez
        $string30 = /XRulezDll_rwdi64\.dll/ nocase ascii wide

    condition:
        any of them
}
