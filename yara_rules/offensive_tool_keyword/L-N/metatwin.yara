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
        $string1 = /\s\-Source\sc\:\\windows\\.{0,1000}\.exe\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string2 = /\s\-Source\sc\:\\windows\\system32\\.{0,1000}\.dll\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string3 = /\/metatwin\.git/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string4 = /\\dist\\sigthief\.exe/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string5 = /\\sigthief\.exe/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string6 = /Invoke\-MetaTwin/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string7 = /metatwin\.ps1/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string8 = /metatwin\-master/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string9 = /sigthief\.exe\.manifest/ nocase ascii wide
        // Description: The project is designed as a file resource cloner. Metadata including digital signature is extracted from one file and injected into another
        // Reference: https://github.com/threatexpress/metatwin
        $string10 = /SigThief\-master/ nocase ascii wide

    condition:
        any of them
}
