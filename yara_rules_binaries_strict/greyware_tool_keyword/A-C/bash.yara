rule bash
{
    meta:
        description = "Detection patterns for the tool 'bash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1 = /bash\s\-c\s.{0,100}curl\s.{0,100}\.sh\s\|\sbash/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /bash\s\-c\s.{0,100}wget\s.{0,100}\.sh\s\|\sbash/ nocase ascii wide
        // Description: bash reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4 = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string5 = /cat\s\/dev\/null\s\>\s.{0,100}bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string6 = /echo\s.{0,100}\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string7 = /echo\s.{0,100}\s\/home\/.{0,100}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string8 = /echo\s.{0,100}\s\/root\/\.bash_history/ nocase ascii wide
        // Description: add a passwordless user 
        // Reference: N/A
        $string9 = /echo\s.{0,100}\:\:0\:0\:\:\/root\:\/bin\/bash.{0,100}\s\>\>\/etc\/passwd/ nocase ascii wide
        // Description: Backdooring APT
        // Reference: N/A
        $string10 = /echo\s.{0,100}APT\:\:Update\:\:Pre\-Invoke\s.{0,100}nohup\sncat\s\-lvp\s.{0,100}\s\-e\s\/bin\/bash\s.{0,100}\s\>\s\/etc\/apt\/apt\.conf\.d\// nocase ascii wide
        // Description: Backdooring Message of the Day
        // Reference: N/A
        $string11 = /echo\s.{0,100}bash\s\-c\s.{0,100}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string12 = /exec\s\/bin\/sh\s0\<\/dev\/tcp\/.{0,100}\/.{0,100}1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string13 = /exec\s5\<\>\/dev\/tcp\/.{0,100}\/.{0,100}.{0,100}cat\s\<\&5\s\|\swhile\sread\sline.{0,100}\sdo\s\$line\s2\>\&5\s\>\&5.{0,100}\sdone/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string14 = "export HISTFILE=/dev/null" nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string15 = "export HISTFILESIZE=0" nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string16 = "export HISTFILESIZE=0" nocase ascii wide
        // Description: use a space in front of your bash command and it won't be logged with the following option
        // Reference: N/A
        $string17 = "HISTCONTROL=ignoredups:ignorespace" nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string18 = "history -c" nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: N/A
        $string19 = "HISTORY=/dev/null" nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string20 = /ln\s\-sf\s\/dev\/null\s.{0,100}bash_history/ nocase ascii wide
        // Description: Bash Keylogger
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21 = /PROMPT_COMMAND\=.{0,100}history\s\-a.{0,100}\stail\s.{0,100}\.bash_history\s\>\s\/dev\/tcp\/127\.0\.0\.1\// nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string22 = /rm\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string23 = /rm\s\/home\/.{0,100}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string24 = /rm\s\/root\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string25 = /set\shistory\s\+o/ nocase ascii wide
        // Description: Equation Group reverse shell method - simple bash reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string26 = /sh\s\>\/dev\/tcp\/.{0,100}\s\<\&1\s2\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string27 = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string28 = /truncate\s\-s0\s.{0,100}bash_history\'/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string29 = "unset HISTFILE" nocase ascii wide
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
