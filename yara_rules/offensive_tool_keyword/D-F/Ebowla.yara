rule Ebowla
{
    meta:
        description = "Detection patterns for the tool 'Ebowla' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ebowla"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string1 = /\sebowla\.py/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string2 = /\/Ebowla\.git/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string3 = /\/ebowla\.py/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string4 = /\\ebowla\.py/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string5 = /DllLoaderLoader\.exe/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string6 = /Ebowla\-master\.zip/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string7 = /exe_dll_shellcode\sgenetic\.config/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string8 = /Genetic\-Malware\/Ebowla/ nocase ascii wide

    condition:
        any of them
}
