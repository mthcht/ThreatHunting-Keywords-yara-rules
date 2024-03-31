rule sshtunnel
{
    meta:
        description = "Detection patterns for the tool 'sshtunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string1 = /\sinstall\s\-c\sconda\-forge\ssshtunnel/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string2 = /\s\-m\ssshtunnel\s/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string3 = /\ssshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string4 = /\sSSHTunnelForwarder\(/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string5 = /\/sshtunnel\s\-/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string6 = /\/sshtunnel\.git/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string7 = /\/sshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string8 = /\/sshtunnel\/tarball\// nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string9 = /\/sshtunnel\/zipball\// nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string10 = /\\sshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string11 = /c89b4490de04897b1c16e5dae1c10ef10e60c56294bd4ca45d1669f5dcb6f9e3/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string12 = /Creating\sSSHTunnelForwarder.{0,1000}paramiko/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string13 = /easy_install\ssshtunnel/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string14 = /from\ssshtunnel\simport\s/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string15 = /from\ssshtunnel\simport\sSSHTunnelForwarder/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string16 = /import\ssshtunnel/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string17 = /pahaz\/sshtunnel/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string18 = /pip\sinstall\ssshtunnel/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string19 = /sshtunnel\.readthedocs\.io/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string20 = /sshtunnel\.readthedocs\.org/ nocase ascii wide

    condition:
        any of them
}
