rule advanced_ip_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string1 = /.{0,1000}Advanced\sIP\sScanner.{0,1000}/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string2 = /.{0,1000}advanced_ip_scanner.{0,1000}/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string3 = /.{0,1000}Advanced_IP_Scanner.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string4 = /.{0,1000}https:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
