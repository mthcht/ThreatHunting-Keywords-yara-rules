rule find
{
    meta:
        description = "Detection patterns for the tool 'find' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "find"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /dir\s\/a\sC:\\pagefile\.sys\s\|\sfindstr\s\/R\s/ nocase ascii wide
        // Description: It can be used to break out from restricted environments by spawning an interactive system shell.
        // Reference: N/A
        $string2 = /find\s\.\s\-exec\s\/bin\/sh\s\\\;\s\-quit/ nocase ascii wide
        // Description: Find sensitive files
        // Reference: N/A
        $string3 = /find\s\/\s\-name\sauthorized_keys\s.{0,1000}\>\s\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string4 = /find\s\/\s\-name\sid_dsa\s2\>/ nocase ascii wide
        // Description: Find sensitive files
        // Reference: N/A
        $string5 = /find\s\/\s\-name\sid_rsa\s.{0,1000}\>\s\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string6 = /find\s\/\s\-name\sid_rsa\s2\>/ nocase ascii wide
        // Description: Find SGID enabled files
        // Reference: N/A
        $string7 = /find\s\/\s\-perm\s\/2000\s\-ls\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string8 = /find\s\/\s\-perm\s\+4000\s\-type\sf\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SGID enabled files
        // Reference: N/A
        $string9 = /find\s\/\s\-perm\s\+8000\s\-ls\s2\>\/dev\/null/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string10 = /find\s\/\s\-perm\s\-2000/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string11 = /find\s\/\s\-perm\s\-4000/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string12 = /find\s\/\s\-perm\s\-4000\s\-type\sf\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string13 = /find\s\/\s\-perm\s\-g\=s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string14 = /find\s\/\s\-perm\s\-u\=s/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string15 = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string16 = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s\-group\s.{0,1000}\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string17 = /find\s\/\s\-uid\s0\s\-perm\s\-4000\s\-type\sf\s/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string18 = /find\s\/\s\-user\sroot\s\-perm\s\-6000\s\-type\sf\s2\>/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string19 = /find\s\/.{0,1000}\s\-perm\s\-04000\s\-o\s\-perm\s\-02000/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string20 = /find\s\/.{0,1000}\s\-perm\s\-u\=s\s\-type\sf\s2\>/ nocase ascii wide

    condition:
        any of them
}
