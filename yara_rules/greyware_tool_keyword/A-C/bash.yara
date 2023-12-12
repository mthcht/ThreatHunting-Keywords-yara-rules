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
        $string1 = /bash\s\-c\s.{0,1000}curl\s.{0,1000}\.sh\s\|\sbash/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /bash\s\-c\s.{0,1000}wget\s.{0,1000}\.sh\s\|\sbash/ nocase ascii wide
        // Description: bash reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4 = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string5 = /cat\s\/dev\/null\s\>\s.{0,1000}bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string6 = /echo\s.{0,1000}\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string7 = /echo\s.{0,1000}\s\/home\/.{0,1000}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string8 = /echo\s.{0,1000}\s\/root\/\.bash_history/ nocase ascii wide
        // Description: add a passwordless user 
        // Reference: N/A
        $string9 = /echo\s.{0,1000}::0:0::\/root:\/bin\/bash.{0,1000}\s\>\>\/etc\/passwd/ nocase ascii wide
        // Description: Backdooring APT
        // Reference: N/A
        $string10 = /echo\s.{0,1000}APT::Update::Pre\-Invoke\s.{0,1000}nohup\sncat\s\-lvp\s.{0,1000}\s\-e\s\/bin\/bash\s.{0,1000}\s\>\s\/etc\/apt\/apt\.conf\.d\// nocase ascii wide
        // Description: Backdooring Message of the Day
        // Reference: N/A
        $string11 = /echo\s.{0,1000}bash\s\-c\s.{0,1000}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string12 = /exec\s\/bin\/sh\s0\<\/dev\/tcp\/.{0,1000}\/.{0,1000}1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string13 = /exec\s5\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}.{0,1000}cat\s\<\&5\s\|\swhile\sread\sline.{0,1000}\sdo\s\$line\s2\>\&5\s\>\&5.{0,1000}\sdone/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string14 = /export\sHISTFILE\=\/dev\/null/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string15 = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string16 = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: use a space in front of your bash command and it won't be logged with the following option
        // Reference: N/A
        $string17 = /HISTCONTROL\=ignoredups:ignorespace/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string18 = /history\s\-c/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string19 = /ln\s\-sf\s\/dev\/null\s.{0,1000}bash_history/ nocase ascii wide
        // Description: Bash Keylogger
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string20 = /PROMPT_COMMAND\=.{0,1000}history\s\-a.{0,1000}\stail\s.{0,1000}\.bash_history\s\>\s\/dev\/tcp\/127\.0\.0\.1\// nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string21 = /rm\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string22 = /rm\s\/home\/.{0,1000}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string23 = /rm\s\/root\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string24 = /set\shistory\s\+o/ nocase ascii wide
        // Description: Equation Group reverse shell method - simple bash reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string25 = /sh\s\>\/dev\/tcp\/.{0,1000}\s\<\&1\s2\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string26 = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string27 = /truncate\s\-s0\s.{0,1000}bash_history\'/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string28 = /unset\sHISTFILE/ nocase ascii wide

    condition:
        any of them
}
