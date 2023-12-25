rule advanced_port_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string1 = /\/lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string2 = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string3 = /\\lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string4 = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string5 = /advanced_port_scanner\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string6 = /advanced_port_scanner_console\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string7 = /lansearch\.exe\s/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string8 = /lansearchpro_portable\.zip/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string9 = /lansearchpro_setup\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string10 = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide

    condition:
        any of them
}
