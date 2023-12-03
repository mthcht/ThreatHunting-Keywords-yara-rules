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
        $string1 = /.{0,1000}\/lansearch\.exe.{0,1000}/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string2 = /.{0,1000}\\lansearch\.exe.{0,1000}/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string3 = /.{0,1000}Advanced_Port_Scanner_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string4 = /.{0,1000}lansearch\.exe\s.{0,1000}/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string5 = /.{0,1000}lansearchpro_portable\.zip.{0,1000}/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string6 = /.{0,1000}lansearchpro_setup\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
