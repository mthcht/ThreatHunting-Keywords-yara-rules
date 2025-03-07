rule find
{
    meta:
        description = "Detection patterns for the tool 'find' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "find"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: truncate every file under /var/log to size 0 - no log content = no forensic.
        // Reference: N/A
        $string1 = /\s\/var\/log\s\-type\sf\s\-exec\s.{0,100}\/tr.{0,100}\s\-s\s0\s\{\}\s\\/
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string2 = " -perm -4000 -o -perm -2000"
        // Description: It can be used to break out from restricted environments by spawning an interactive system shell.
        // Reference: N/A
        $string3 = /find\s\.\s\-exec\s\/bin\/sh\s\\\;\s\-quit/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string4 = /find\s\.\s\-perm\s\-2\s\-ls/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string5 = /find\s\.\s\-type\sf\s\-name\s\.bash_history/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string6 = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string7 = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string8 = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string9 = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string10 = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/
        // Description: Find sensitive files
        // Reference: N/A
        $string11 = /find\s\/\s\-name\sauthorized_keys\s.{0,100}\>\s\/dev\/null/
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string12 = "find / -name ftp"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string13 = "find / -name id_dsa 2>"
        // Description: Find sensitive files
        // Reference: N/A
        $string14 = /find\s\/\s\-name\sid_rsa\s.{0,100}\>\s\/dev\/null/
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string15 = "find / -name id_rsa 2>"
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string16 = "find / -name netcat"
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string17 = /find\s\/\s\-name\stftp.{0,100}\s/
        // Description: Find SGID enabled files
        // Reference: N/A
        $string18 = "find / -perm /2000 -ls 2>/dev/null"
        // Description: Find SUID enabled files
        // Reference: N/A
        $string19 = /find\s\/\s\-perm\s\+4000\s\-type\sf\s2\>\/dev\/null/
        // Description: Find SGID enabled files
        // Reference: N/A
        $string20 = /find\s\/\s\-perm\s\+8000\s\-ls\s2\>\/dev\/null/
        // Description: searches for directories that have the sticky bit set
        // Reference: N/A
        $string21 = "find / -perm -1000 -type d 2>/dev/null"
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string22 = "find / -perm -2 -ls"
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string23 = "find / -perm -2000"
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string24 = "find / -perm -4000"
        // Description: Find SUID enabled files
        // Reference: N/A
        $string25 = "find / -perm -4000 -type f "
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string26 = "find / -perm -g=s"
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string27 = "find / -perm -g=s -o -perm -u=s -type f 2>/dev/null"
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string28 = "find / -perm -g=s -type f 2>/dev/null"
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string29 = "find / -perm -u=s"
        // Description: Find SUID enabled files
        // Reference: N/A
        $string30 = "find / -perm -u=s -type f 2>/dev/null"
        // Description: Look for files with the SGID (Set Group ID) bit set
        // Reference: N/A
        $string31 = "find / -perm -u=s -type f 2>/dev/null"
        // Description: Find SUID enabled files
        // Reference: N/A
        $string32 = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s\-group\s.{0,100}\/dev\/null/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string33 = /find\s\/\s\-type\sf\s\-name\s\.bash_history/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string34 = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string35 = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string36 = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string37 = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string38 = "find / -type f -perm -02000 -ls"
        // Description: find commands used by the wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string39 = "find / -type f -perm -04000 -ls"
        // Description: Find SUID enabled files
        // Reference: N/A
        $string40 = "find / -uid 0 -perm -4000 -type f "
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string41 = "find / -user root -perm -6000 -type f 2>"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string42 = /find\s\/.{0,100}\s\-perm\s\-04000\s\-o\s\-perm\s\-02000/
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string43 = /find\s\/.{0,100}\s\-perm\s\-u\=s\s\-type\sf\s2\>/
        // Description: truncate every file under /var/log to size 0 - no log content = no forensic.
        // Reference: N/A
        $string44 = /find\s\/var\/log\s\-type\sf\s\-exec\struncate\s\-s\s0\s\{\}\s\\/
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
