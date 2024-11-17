rule shell
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string1 = /\/bin\/sh\s\|\snc/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string2 = /\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string3 = /rm\s\-f\sbackpipe.{0,100}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string4 = /sc\sconfig\sWinDefend\sstart\=\sdisabled/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string5 = /schkconfig\soff\scbdaemon/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string6 = /service\scbdaemon\sstop/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string7 = /socket\(S.{0,100}PF_INET.{0,100}SOCK_STREAM.{0,100}getprotobyname\(.{0,100}tcp.{0,100}\)\).{0,100}if\(connect\(S.{0,100}sockaddr_in\(\$p.{0,100}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string8 = /STDIN\-\>fdopen\(\$c.{0,100}r\).{0,100}\$\~\-\>fdopen\(\$c.{0,100}w\).{0,100}system\$_\swhile\<\>/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string9 = /uname\s\-a.{0,100}\sw.{0,100}\sid.{0,100}\s\/bin\/bash\s\-i/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string10 = /setenforce\s0/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
