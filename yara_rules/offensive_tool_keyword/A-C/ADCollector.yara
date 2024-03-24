rule ADCollector
{
    meta:
        description = "Detection patterns for the tool 'ADCollector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCollector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string1 = /\s\s\-\-LocalGMEnum\s\-\-Host\s/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string2 = /\sADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string3 = /\s\-\-SessionEnum\s\-\-Host\s/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string4 = /\s\-\-UserEnum\s\-\-Host\s/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string5 = /\.exe\s\-\-ACLScan\s.{0,1000}\s\-\-OU\s/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string6 = /\.exe\s\-\-LDAPs\s\-\-DisableSigning/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string7 = /\/ADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string8 = /\/ADCollector\.git/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string9 = /\\ADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string10 = /\\ADCollector3\.sln/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string11 = /\\ADCollector3\\/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string12 = /16e9f3c3f2a4264e3be9d2ddfe8d4ad409f4db17c077efd372389fbfe89f727b/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string13 = /558a73bf1f4a3ecc59133a10d1a7892712f2bd30326f86a12d5c7060274d734d/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string14 = /ADCollector3\.csproj/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string15 = /D1AE1ACF\-8AA2\-4935\-ACDF\-EC22BAE2DF76/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string16 = /dev\-2null\/ADCollector/ nocase ascii wide

    condition:
        any of them
}
