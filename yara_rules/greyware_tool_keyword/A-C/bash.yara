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
        $string1 = /.{0,1000}bash\s\-c\s.{0,1000}curl\s.{0,1000}\.sh\s\|\sbash.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /.{0,1000}bash\s\-c\s.{0,1000}wget\s.{0,1000}\.sh\s\|\sbash.{0,1000}/ nocase ascii wide
        // Description: bash reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /.{0,1000}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1.{0,1000}/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4 = /.{0,1000}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1.{0,1000}/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string5 = /.{0,1000}cat\s\/dev\/null\s\>\s.{0,1000}bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string6 = /.{0,1000}echo\s.{0,1000}\s\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string7 = /.{0,1000}echo\s.{0,1000}\s\/home\/.{0,1000}\/\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string8 = /.{0,1000}echo\s.{0,1000}\s\/root\/\.bash_history.{0,1000}/ nocase ascii wide
        // Description: add a passwordless user 
        // Reference: N/A
        $string9 = /.{0,1000}echo\s.{0,1000}::0:0::\/root:\/bin\/bash.{0,1000}\s\>\>\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: Backdooring APT
        // Reference: N/A
        $string10 = /.{0,1000}echo\s.{0,1000}APT::Update::Pre\-Invoke\s.{0,1000}nohup\sncat\s\-lvp\s.{0,1000}\s\-e\s\/bin\/bash\s.{0,1000}\s\>\s\/etc\/apt\/apt\.conf\.d\/.{0,1000}/ nocase ascii wide
        // Description: Backdooring Message of the Day
        // Reference: N/A
        $string11 = /.{0,1000}echo\s.{0,1000}bash\s\-c\s.{0,1000}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header.{0,1000}/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string12 = /.{0,1000}exec\s\/bin\/sh\s0\<\/dev\/tcp\/.{0,1000}\/.{0,1000}1\>\&0\s2\>\&0.{0,1000}/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string13 = /.{0,1000}exec\s5\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}.{0,1000}cat\s\<\&5\s\|\swhile\sread\sline.{0,1000}\sdo\s\$line\s2\>\&5\s\>\&5.{0,1000}\sdone.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string14 = /.{0,1000}export\sHISTFILE\=\/dev\/null.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string15 = /.{0,1000}export\sHISTFILESIZE\=0.{0,1000}/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string16 = /.{0,1000}export\sHISTFILESIZE\=0.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string17 = /.{0,1000}history\s\-c.{0,1000}/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string18 = /.{0,1000}ln\s\-sf\s\/dev\/null\s.{0,1000}bash_history.{0,1000}/ nocase ascii wide
        // Description: Bash Keylogger
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string19 = /.{0,1000}PROMPT_COMMAND\=.{0,1000}history\s\-a.{0,1000}\stail\s.{0,1000}\.bash_history\s\>\s\/dev\/tcp\/127\.0\.0\.1\/.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string20 = /.{0,1000}rm\s\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string21 = /.{0,1000}rm\s\/home\/.{0,1000}\/\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string22 = /.{0,1000}rm\s\/root\/\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string23 = /.{0,1000}set\shistory\s\+o.{0,1000}/ nocase ascii wide
        // Description: Equation Group reverse shell method - simple bash reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string24 = /.{0,1000}sh\s\>\/dev\/tcp\/.{0,1000}\s\<\&1\s2\>\&1.{0,1000}/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string25 = /.{0,1000}sh\s\-i\s\>\&\s\/dev\/udp\/.{0,1000}\/.{0,1000}\s0\>\&1.{0,1000}/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string26 = /.{0,1000}truncate\s\-s0\s.{0,1000}bash_history\'.{0,1000}/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string27 = /.{0,1000}unset\sHISTFILE.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
