rule spoolsploit
{
    meta:
        description = "Detection patterns for the tool 'spoolsploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoolsploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string1 = /.{0,1000}\s\-a\snightmare.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string2 = /.{0,1000}\s\-a\sspoolsample.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string3 = /.{0,1000}\sevil\.corp\s.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string4 = /.{0,1000}\sspoolsploit\s.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string5 = /.{0,1000}\/smbserver\/smb_server\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string6 = /.{0,1000}\/ssploit\/.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string7 = /.{0,1000}\-\-attack\snightmare.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string8 = /.{0,1000}\-\-attack\sspoolsample.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string9 = /.{0,1000}BeetleChunks\/SpoolSploit.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string10 = /.{0,1000}impacket\..{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string11 = /.{0,1000}malicious\.dll.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string12 = /.{0,1000}PrintNightmare\..{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string13 = /.{0,1000}spool_sploit\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string14 = /.{0,1000}SpoolSploit\/.{0,1000}/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string15 = /.{0,1000}spoolsploit:latest.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
