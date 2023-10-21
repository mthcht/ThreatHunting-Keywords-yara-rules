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
        $string2 = /\\lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string3 = /Advanced_Port_Scanner_.*\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string4 = /lansearch\.exe\s/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string5 = /lansearchpro_portable\.zip/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string6 = /lansearchpro_setup\.exe/ nocase ascii wide

    condition:
        any of them
}