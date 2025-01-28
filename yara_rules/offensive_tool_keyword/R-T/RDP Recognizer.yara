rule RDP_Recognizer
{
    meta:
        description = "Detection patterns for the tool 'RDP Recognizer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDP Recognizer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string1 = /\/RDP\sRecognizer\.exe/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string2 = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass1\.txt/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string3 = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass2\.txt/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string4 = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass3\.txt/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string5 = /\\Brute\sRDP\.rar/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string6 = /\\RDP\sRecognizer\.exe/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string7 = /\\RDP\sRecognizer\.pdb/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string8 = /\\RDP\sRecognizer1\.exe/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string9 = /\\RDP\sRecognizer3\.exe/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string10 = /\>1047\@exploit\.im\</ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string11 = ">Penetration test tool<" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string12 = ">RDP Recognizer<" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string13 = "1e05c9543989d8f9034dcd87f662ef8319c624a1988b800ad77676f55a2bc538" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string14 = "491919ffbf3bf3ba309a98d7dce8c3b04e4f269faedd59f57ec1943efe668254" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string15 = "55d8c97ec4476f7ada4f2991de85f6ddb973ac4634dc0a08e2c731d75c5700b3" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string16 = "74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string17 = "ac0eb86fafd0ca2e1450238cfb023c1c82b6d24fec249623ff1d0e161b7727c6" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string18 = "ac0eb86fafd0ca2e1450238cfb023c1c82b6d24fec249623ff1d0e161b7727c6" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string19 = /attrib\s\+r\s\+a\s\+s\s\+h\s\\"\%PROGRAMFILES\%\\Media\splayer\\"\s\/S\s\/D/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string20 = "RDP Recognizer Login Parser" nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string21 = /reg\sdelete\s\\"HKLM\\SYSTEM\\Remote\sManipulator\sSystem\\"\s\/f/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string22 = /taskkill\s\/f\s\/im\srfusclient\.exe/ nocase ascii wide
        // Description: could be used to brute force RDP passwords or check for RDP vulnerabilities
        // Reference: https://www.virustotal.com/gui/file/74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6/details
        $string23 = /taskkill\s\/f\s\/im\srutserv\.exe/ nocase ascii wide

    condition:
        any of them
}
