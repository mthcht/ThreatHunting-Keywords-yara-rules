rule metatwin
{
    meta:
        description = "Detection patterns for the tool 'metatwin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metatwin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string1 = /.{0,1000}\s\-Source\sc:\\windows\\.{0,1000}\.exe\s\-Target\s.{0,1000}\.exe\s\-Sign.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string2 = /.{0,1000}\s\-Source\sc:\\windows\\system32\\.{0,1000}\.dll\s\-Target\s.{0,1000}\.exe\s\-Sign.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string3 = /.{0,1000}\/metatwin\.git.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string4 = /.{0,1000}\\dist\\sigthief\.exe.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string5 = /.{0,1000}\\sigthief\.exe.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string6 = /.{0,1000}Invoke\-MetaTwin.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string7 = /.{0,1000}metatwin\.ps1.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string8 = /.{0,1000}metatwin\-master.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string9 = /.{0,1000}sigthief\.exe\.manifest.{0,1000}/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string10 = /.{0,1000}SigThief\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
