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
        $string1 = " CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string2 = " received ACK from backdoor"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string3 = /\.\/injector\s\-/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string4 = /\/etc\/cron\.d\/ebpfbackdoor/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string5 = /\/etc\/sudoers\.d\/ebpfbackdoor/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string6 = "/execve_hijack"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string7 = /\/injection_lib\.so/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string8 = /\/src\/common\/c\&c\.h/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string9 = "/TFG/src/helpers/execve_hijack"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string10 = /\/TripleCross\.git/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string11 = "/TripleCross/apps/"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string12 = /\/TripleCross\-0\.1\.0\.zip/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string13 = /\/TripleCross\-0\.1\.0\//
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string14 = /\>\>\sWhere\sto\shide\sthe\spayload\?\sSelect\sa\snumber\:\s/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string15 = "Activate all of rootkit's hooks"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string16 = /activate_command_control_shell\(/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string17 = /activate_command_control_shell_encrypted\(/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string18 = "Activated COMMAND & CONTROL encrypted shell"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string19 = "Activated COMMAND & CONTROL shell"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string20 = "Activating COMMAND & CONTROL with MULTI-PACKET backdoor trigger"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string21 = "Backdoor did not understand the request"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string22 = "Backdoor sent unrecognizable message:"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string23 = "Crafting malicious SYN packet"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string24 = "Detected possible phantom shell command"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string25 = "h3xduck/TripleCross"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string26 = "Libbpf-powered rootkit"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string27 = "Malicious program execve hijacker executed"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string28 = "PATH_EXECUTION_HIJACK_PROGRAM"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string29 = "Rootkit is already installed"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string30 = "Running hijacking process"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string31 = "Sending malicious packet to infected machine"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string32 = "Sending malicious packet to infected machine"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string33 = "Spawn a phantom shell - with pattern-based trigger"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string34 = "Spawn encrypted pseudo-shell with IP - with "
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string35 = "Spawn plaintext pseudo-shell with IP - using "
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string36 = /The\sbackdoor\sjust\ssignaled\san\sACK\.\sThis\sshould\snot\shave\shappened/
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string37 = "Waiting for rootkit response"
        // Description: A Linux eBPF rootkit with a backdoor - C2 - library injection - execution hijacking -  persistence and stealth capabilities.
        // Reference: https://github.com/h3xduck/TripleCross
        $string38 = /xdp\/backdoor\.h/

    condition:
        any of them
}
