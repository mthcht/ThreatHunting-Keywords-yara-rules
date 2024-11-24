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
        $string1 = /\/Advanced_Port_Scanner_.{0,1000}\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string2 = /\/lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string3 = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string4 = /\\lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string5 = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string6 = ">Advanced Port Scanner Setup<" nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string7 = ">Advanced Port Scanner<" nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string8 = /advanced_port_scanner\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string9 = /advanced_port_scanner_console\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string10 = "d0c1662ce239e4d288048c0e3324ec52962f6ddda77da0cb7af9c1d9c2f1e2eb" nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string11 = /http\:\/\/www\.advanced\-port\-scanner\.com\/checkupdate\.php/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string12 = /lansearch\.exe\s/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string13 = /lansearchpro_portable\.zip/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string14 = /lansearchpro_setup\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string15 = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide

    condition:
        any of them
}
