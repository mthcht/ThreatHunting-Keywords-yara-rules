rule _
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string1 = /.{0,1000}\/keygen\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string2 = /.{0,1000}\\1\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string3 = /.{0,1000}\\1\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string4 = /.{0,1000}\\1\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string5 = /.{0,1000}\\2\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string6 = /.{0,1000}\\2\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string7 = /.{0,1000}\\2\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string8 = /.{0,1000}\\3\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string9 = /.{0,1000}\\3\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string10 = /.{0,1000}\\3\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string11 = /.{0,1000}\\4\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string12 = /.{0,1000}\\4\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string13 = /.{0,1000}\\4\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string14 = /.{0,1000}\\5\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string15 = /.{0,1000}\\5\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string16 = /.{0,1000}\\5\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string17 = /.{0,1000}\\6\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string18 = /.{0,1000}\\6\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string19 = /.{0,1000}\\6\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string20 = /.{0,1000}\\7\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string21 = /.{0,1000}\\7\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string22 = /.{0,1000}\\7\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string23 = /.{0,1000}\\8\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string24 = /.{0,1000}\\8\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string25 = /.{0,1000}\\8\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string26 = /.{0,1000}\\9\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string27 = /.{0,1000}\\9\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string28 = /.{0,1000}\\9\.exe/ nocase ascii wide
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string29 = /.{0,1000}\\keygen\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
