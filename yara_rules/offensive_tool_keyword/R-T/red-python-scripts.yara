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
        $string1 = /.{0,1000}arp_mitm\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string2 = /.{0,1000}change\-windows10\-mac\-address\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string3 = /.{0,1000}lanscan_arp\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string4 = /.{0,1000}nmap_port_scanner\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string5 = /.{0,1000}nmap_port_scanner_ip_obj\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string6 = /.{0,1000}port_scanner_ip_obj\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string7 = /.{0,1000}port_scanner_regex\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string8 = /.{0,1000}wifi_dos_own\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string9 = /.{0,1000}wifi_dos3\.py.{0,1000}/ nocase ascii wide
        // Description: random networking exploitation scirpts
        // Reference: https://github.com/davidbombal/red-python-scripts
        $string10 = /.{0,1000}yeelight_discover\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
