rule EQGRP_tools
{
    meta:
        description = "Detection patterns for the tool 'EQGRP tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGRP tools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Equation Group hack tool leaked by ShadowBrokers- file emptybowl.py RCE for MailCenter Gateway (mcgate) - an application that comes with Asia Info Message Center mailserver  buffer overflow allows a string passed to popen() call to be controlled by an attacker  arbitraty cmd execute known to work only for AIMC Version 2.9.5.1
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/emptybowl.py
        $string1 = /\<\s\/dev\/console\s\|\suudecode\s\&\&\suncompress/ nocase ascii wide
        // Description: Equation Group hack tool leaked note defense evasion
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/Auditcleaner
        $string2 = /\>\s\/var\/log\/audit\/audit\.log.{0,100}\srm\s\-f\s\./ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string3 = /127\.0\.0\.1\sis\snot\sadvisable\sas\sa\ssource\.\sUse\s\-l\s127\.0\.0\.1\sto\soverride\sthis\swarning/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string4 = /Attempting\sconnection\sfrom\s0\.0\.0\.0\:/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers anti forensic - cleans up audit.log
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/Auditcleaner
        $string5 = /Auditcleaner\./ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file ELATEDMONKEY is a local privelege escalation exploit against systems running the cPanel Remote Management Web Interface 
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/user.tool.elatedmonkey
        $string6 = /cat\s\>\s\/dev\/tcp\/127\.0\.0\.1.{0,100}\<\<END/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  Anti forensic: Manipulate utmp
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/old/etc/user.tool.dubmoat.COMMON
        $string7 = /chmod\s666\s\/var\/run\/utmp\~/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers - EncTelnet/Poptop To use Nopen over an existing connection
        // Reference: https://github.com/thePevertedSpartan/EQ1/blob/0c2354ff1073099b2aa417030b3167ec29d7279c/Linux/doc/old/etc/user.tool.poptop.COMMON
        $string8 = /chmod\s700\snscd\scrond/ nocase ascii wide
        // Description: Equation Group hack tool leaked note defense evasion
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/Auditcleaner
        $string9 = /cp\s\/var\/log\/audit\/audit\.log\s\.tmp/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  Anti forensic: Manipulate utmp
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/old/etc/user.tool.dubmoat.COMMON
        $string10 = /dubmoat/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  Anti forensic: Manipulate utmp
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/old/etc/user.tool.dubmoat.COMMON
        $string11 = /Dubmoat_ExtractData/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  Anti forensic: Manipulate utmp
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/old/etc/user.tool.dubmoat.COMMON
        $string12 = /Dubmoat_PrintFilename/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  Anti forensic: Manipulate utmp
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/doc/old/etc/user.tool.dubmoat.COMMON
        $string13 = /Dubmoat_TruncateFile/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file echowrecker. samba 2.2 and 3.0.2a - 3.0.12-5 RCE (with DWARF symbols)  for FreeBSD  OpenBSD 3.1  OpenBSD 3.2 (with a non-executable stack  zomg)  and Linux. Likely CVE-2003-0201. There is also a Solaris version
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/echowrecker
        $string14 = /echowrecker/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file emptybowl.py RCE for MailCenter Gateway (mcgate) - an application that comes with Asia Info Message Center mailserver  buffer overflow allows a string passed to popen() call to be controlled by an attacker  arbitraty cmd execute known to work only for AIMC Version 2.9.5.1
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/emptybowl.py
        $string15 = /emptybowl\.py/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file ewok (snmpwalk like)
        // Reference: https://github.com/wolf-project/NSA-TOOLS-SHADOW-BROKERS
        $string16 = /ewok\s\-t\s/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- from files ftshell File transfer shell
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/ftshell.v3.10.2.1
        $string17 = /ftshell\s\-/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- from files ftshell File transfer shell
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/ftshell.v3.10.2.1
        $string18 = /ftshell\.v3/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  ghost:statmon/tooltalk privesc
        // Reference: https://github.com/x0rz/EQGRP/tree/master/Linux/bin
        $string19 = /ghost_.{0,100}\s\-v/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  ghost:statmon/tooltalk privesc
        // Reference: https://github.com/x0rz/EQGRP/tree/master/Linux/bin
        $string20 = /ghost_sparc/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file  ghost:statmon/tooltalk privesc
        // Reference: https://github.com/x0rz/EQGRP/tree/master/Linux/bin
        $string21 = /ghost_x86/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string22 = /iptables\s\-\%c\sOUTPUT\s\-p\stcp\s\-d\s127\.0\.0\.1\s\-\-tcp\-flags\sRST\sRST\s\-j\sDROP\s/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string23 = /noclient\:\sfailed\sto\sexecute\s\%s\:\s\%s/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- from files ftshell File transfer shell
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/ftshell.v3.10.2.1
        $string24 = /ourtn\-ftshell\-upcommand/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- from files ftshell File transfer shell
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/ftshell.v3.10.2.1
        $string25 = /send\s\\.{0,100}\\\[\s\\\\.{0,100}\\\$BASH\\\\.{0,100}\s\=\s\\\\.{0,100}\/bin\/bash\\\\.{0,100}\s\-o\s\\\\.{0,100}\\\$SHELL\\\\.{0,100}\s\=\s\\\\.{0,100}\/bin\/bash\\\\.{0,100}\s\\\]/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file emptybowl.py RCE for MailCenter Gateway (mcgate) - an application that comes with Asia Info Message Center mailserver  buffer overflow allows a string passed to popen() call to be controlled by an attacker  arbitraty cmd execute known to work only for AIMC Version 2.9.5.1
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/emptybowl.py
        $string26 = /sendmail\s\-osendmail\schmod\s\+x\ssendmail/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string27 = /sh\s\-c\s.{0,100}ping\s\-c\s2\s\%s\s\sgrep\s\%s\s\/proc\/net\/arp\s\>\/tmp\/gx\s/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- from files ftshell File transfer shell
        // Reference: https://github.com/Artogn/EQGRP-1/blob/master/Linux/bin/ftshell.v3.10.2.1
        $string28 = /system\srm\s\-f\s\/current\/tmp\/ftshell\.latest/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file echowrecker. samba 2.2 and 3.0.2a - 3.0.12-5 RCE (with DWARF symbols)  for FreeBSD  OpenBSD 3.1  OpenBSD 3.2 (with a non-executable stack  zomg)  and Linux. Likely CVE-2003-0201. There is also a Solaris version
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/echowrecker
        $string29 = /usr\/bin\/wget\s\-O\s\/tmp\/a\shttp.{0,100}\schmod\s755\s\/tmp\/cron/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file noclient CNC server for NOPEN*
        // Reference: https://github.com/x0rz/EQGRP/blob/master/Linux/bin/noclient-3.3.2.3-linux-i386
        $string30 = /noclient\-3\./ nocase ascii wide
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
