rule red_python_scripts
{
    meta:
        description = "Detection patterns for the tool 'red-python-scripts' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red-python-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string1 = /arp_mitm\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string2 = /change\-windows10\-mac\-address\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string3 = /lanscan_arp\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string4 = /nmap_port_scanner\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string5 = /nmap_port_scanner_ip_obj\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string6 = /port_scanner_ip_obj\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string7 = /port_scanner_regex\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string8 = /wifi_dos_own\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string9 = /wifi_dos3\.py/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string10 = /yeelight_discover\.py/ nocase ascii wide

    condition:
        any of them
}
