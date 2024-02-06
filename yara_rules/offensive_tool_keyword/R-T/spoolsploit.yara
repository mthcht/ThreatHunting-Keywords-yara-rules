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
        $string1 = /\s\-a\snightmare/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string2 = /\s\-a\sspoolsample/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string3 = /\sevil\.corp\s/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string4 = /\sspoolsploit\s/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string5 = /\/smbserver\/smb_server\.py/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string6 = /\/ssploit\// nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string7 = /\-\-attack\snightmare/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string8 = /\-\-attack\sspoolsample/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string9 = /BeetleChunks\/SpoolSploit/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string10 = /impacket\./ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string11 = /malicious\.dll/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string12 = /PrintNightmare\./ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string13 = /spool_sploit\.py/ nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string14 = /SpoolSploit\// nocase ascii wide
        // Description: A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.
        // Reference: https://github.com/BeetleChunks/SpoolSploit
        $string15 = /spoolsploit\:latest/ nocase ascii wide

    condition:
        any of them
}
