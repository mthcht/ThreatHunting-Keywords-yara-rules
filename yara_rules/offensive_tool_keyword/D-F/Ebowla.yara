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
        $string1 = /.{0,1000}\sebowla\.py.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string2 = /.{0,1000}\/Ebowla\.git.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string3 = /.{0,1000}\/ebowla\.py.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string4 = /.{0,1000}\\ebowla\.py.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string5 = /.{0,1000}DllLoaderLoader\.exe.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string6 = /.{0,1000}Ebowla\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string7 = /.{0,1000}exe_dll_shellcode\sgenetic\.config.{0,1000}/ nocase ascii wide
        // Description: Framework for Making Environmental Keyed Payloads
        // Reference: https://github.com/Genetic-Malware/Ebowla
        $string8 = /.{0,1000}Genetic\-Malware\/Ebowla.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
