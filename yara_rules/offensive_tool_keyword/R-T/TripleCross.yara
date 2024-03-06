rule TripleCross
{
    meta:
        description = "Detection patterns for the tool 'TripleCross' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TripleCross"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string1 = /\sCC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string2 = /\sreceived\sACK\sfrom\sbackdoor/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string3 = /\.\/injector\s\-/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string4 = /\/etc\/cron\.d\/ebpfbackdoor/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string5 = /\/etc\/sudoers\.d\/ebpfbackdoor/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string6 = /\/execve_hijack/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string7 = /\/injection_lib\.so/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string8 = /\/src\/common\/c\&c\.h/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string9 = /\/TFG\/src\/helpers\/execve_hijack/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string10 = /\/TripleCross\.git/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string11 = /\/TripleCross\/apps\// nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string12 = /\/TripleCross\-0\.1\.0\.zip/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string13 = /\/TripleCross\-0\.1\.0\// nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string14 = /\>\>\sWhere\sto\shide\sthe\spayload\?\sSelect\sa\snumber\:\s/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string15 = /Activate\sall\sof\srootkit\'s\shooks/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string16 = /activate_command_control_shell\(/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string17 = /activate_command_control_shell_encrypted\(/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string18 = /Activated\sCOMMAND\s\&\sCONTROL\sencrypted\sshell/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string19 = /Activated\sCOMMAND\s\&\sCONTROL\sshell/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string20 = /Activating\sCOMMAND\s\&\sCONTROL\swith\sMULTI\-PACKET\sbackdoor\strigger/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string21 = /Backdoor\sdid\snot\sunderstand\sthe\srequest/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string22 = /Backdoor\ssent\sunrecognizable\smessage\:/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string23 = /Crafting\smalicious\sSYN\spacket/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string24 = /Detected\spossible\sphantom\sshell\scommand/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string25 = /h3xduck\/TripleCross/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string26 = /Libbpf\-powered\srootkit/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string27 = /Malicious\sprogram\sexecve\shijacker\sexecuted/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string28 = /PATH_EXECUTION_HIJACK_PROGRAM/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string29 = /Rootkit\sis\salready\sinstalled/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string30 = /Running\shijacking\sprocess/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string31 = /Sending\smalicious\spacket\sto\sinfected\smachine/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string32 = /Sending\smalicious\spacket\sto\sinfected\smachine/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string33 = /Spawn\sa\sphantom\sshell\s\-\swith\spattern\-based\strigger/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string34 = /Spawn\sencrypted\spseudo\-shell\swith\sIP\s\-\swith\s/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string35 = /Spawn\splaintext\spseudo\-shell\swith\sIP\s\-\susing\s/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string36 = /The\sbackdoor\sjust\ssignaled\san\sACK\.\sThis\sshould\snot\shave\shappened/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string37 = /Waiting\sfor\srootkit\sresponse/ nocase ascii wide
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string38 = /xdp\/backdoor\.h/ nocase ascii wide

    condition:
        any of them
}
