rule _
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: attempt to bypass security controls or execute commands from an unexpected location
        // Reference: https://twitter.com/malwrhunterteam/status/1737220172220620854/photo/1
        $string1 = /\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\Windows\\System32\\cmd\.exe/ nocase ascii wide
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string2 = /\/keygen\.exe/ nocase ascii wide
        // Description: suspicious file name - has been used by threat actors
        // Reference: N/A
        $string3 = /\/PAYMENTS\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string4 = /\\1\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string5 = /\\1\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string6 = /\\1\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string7 = /\\2\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string8 = /\\2\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string9 = /\\2\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string10 = /\\3\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string11 = /\\3\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string12 = /\\3\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string13 = /\\4\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string14 = /\\4\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string15 = /\\4\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string16 = /\\5\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string17 = /\\5\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string18 = /\\5\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string19 = /\\6\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string20 = /\\6\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string21 = /\\6\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string22 = /\\7\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string23 = /\\7\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string24 = /\\7\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string25 = /\\8\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string26 = /\\8\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string27 = /\\8\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string28 = /\\9\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string29 = /\\9\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string30 = /\\9\.exe/ nocase ascii wide
        // Description: script in startup location
        // Reference: N/A
        $string31 = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\.bat/ nocase ascii wide
        // Description: script in startup location
        // Reference: N/A
        $string32 = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\.cmd/ nocase ascii wide
        // Description: script in startup location
        // Reference: N/A
        $string33 = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\.hta/ nocase ascii wide
        // Description: script in startup location
        // Reference: N/A
        $string34 = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: script in startup location
        // Reference: N/A
        $string35 = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\.vbs/ nocase ascii wide
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string36 = /\\keygen\.exe/ nocase ascii wide
        // Description: suspicious file name - has been used by threat actors
        // Reference: N/A
        $string37 = /\\PAYMENT\.hta/ nocase ascii wide
        // Description: suspicious file name - has been used by threat actors
        // Reference: N/A
        $string38 = /\\PAYMENT\.hta/ nocase ascii wide
        // Description: suspicious file name - has been used by threat actors
        // Reference: N/A
        $string39 = /\\PAYMENTS\.exe/ nocase ascii wide
        // Description: Suspicious tlds with suspicious file types
        // Reference: N/A
        $string40 = /https\:\/\/.{0,1000}\.xyz\/.{0,1000}\.ps1/ nocase ascii wide

    condition:
        any of them
}
