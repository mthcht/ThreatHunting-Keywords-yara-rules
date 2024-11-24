rule AutoSUID
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string1 = /\spwn_tclsh\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string2 = /\sWe\shave\sfound\sat\sleast\s.{0,100}\spotential\sSUID\sexploitable\sfile\(s\)/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string3 = /\.\/capsh\s\-\-gid\=0\s\-\-uid\=0\s\-\-/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string4 = /\.\/chroot\s\/\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string5 = /\.\/env\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string6 = /\.\/expect\s\-c\s\'spawn\s\/bin\/sh\s\-p\;interact\'/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string7 = /\.\/flock\s\-u\s\/\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string8 = /\.\/nice\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string9 = /\.\/rview\s\-c\s\'\:py3\simport\sos.{0,100}os\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string10 = /\/ld\.so\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string11 = "/perf stat /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string12 = /\/perl\s\-e\s\'exec\s\\\\"\/bin\/sh\\\\"/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string13 = /\/pwn_tclsh\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string14 = /\/rvim\s\-c\s\'\:py3\simport\sos.{0,100}os\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string15 = "/sshpass /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string16 = "/stdbuf -i0 /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string17 = "/unshare -r /bin/sh" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string18 = /\/view\s\-c\s\'\:py3\simport\sos.{0,100}os\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string19 = /\/watch\s\-x\ssh\s\-c\s\'reset.{0,100}\sexec\ssh\s1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string20 = "agetty -o -p -l /bin/sh -a root tty" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string21 = "cpulimit -l 100 -f -- /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string22 = /dmsetup\screate\sbase\s\<\<EOF.{0,100}0\s3534848\slinear\s\/dev\/loop0\s94208.{0,100}\sEOF.{0,100}\.\/dmsetup\sls\s\-\-exec\s\'\/bin\/sh\s\-p\s\-s/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string23 = "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string24 = /emacs\s\-Q\s\-nw\s\-\-eval\s\'\(term\s\\\\"\/bin\/sh\s\-p\\\\"\)/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string25 = /\'exec\s\/bin\/sh\s\-p\s0\<\&1\'\s\>\>\s\\\$TF/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string26 = /find\s\.\s\-exec\s\/bin\/sh\s\-p\s\\\;\s\-quit/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string27 = /find\s\/\s\-xdev\s\-user\sroot\s\\\(\s\-perm\s\-4000\s\-o\s\-perm\s\-2000\s\-o\s\-perm\s\-6000\s\\\)\s2\>\/dev\/null/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string28 = /gdb\s\-nx\s\-ex\s\'python\simport\sos.{0,100}os\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string29 = "genie -c '/bin/sh'" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string30 = /gimp\s\-idf\s\-\-batch\-interpreter\=python\-fu\-eval\s\-b\s\'import\sos.{0,100}\sos\.execl\(.{0,100}\/bin\/sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string31 = "ionice /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string32 = "logsave /dev/null /bin/sh -i -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string33 = "msgfilter -P /bin/sh -p -c '/bin/sh" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string34 = /php\s\-r\s\\\\"pcntl_exec\(\'\/bin\/sh\'/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string35 = /rsync\s\-e\s\'sh\s\-p\s\-c\s.{0,100}sh\s0\<\&2\s1\>\&2.{0,100}127\.0\.0\.1\:\/dev\/null/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string36 = "strace -o /dev/null /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string37 = "taskset 1 /bin/sh -p" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string38 = /vim\s\-c\s\'\:py3\simport\sos.{0,100}\sos\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string39 = /vimdiff\s\-c\s\'\:py3\simport\sos.{0,100}\sos\.execl\(\\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string40 = "xargs -a /dev/null sh -p" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
