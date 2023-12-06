rule monkey
{
    meta:
        description = "Detection patterns for the tool 'monkey' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "monkey"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string1 = /\.\/monkey\.sh/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string2 = /\/infection_monkey\// nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string3 = /\/log4shell\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string4 = /\/monkey\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string5 = /\/monkey_island\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string6 = /\/shellshock\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string7 = /\/smbexec\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string8 = /\/timestomping\.ps1/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string9 = /\/trap_command\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string10 = /\/web_rce\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string11 = /\/zerologon\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string12 = /\\monkey\.exe\s/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string13 = /\\monkey32\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string14 = /\\monkey64\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string15 = /clear_command_history\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string16 = /communicate_as_backdoor_user\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string17 = /dump_secrets\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string18 = /guardicore\/monkey/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string19 = /hook\-infection_monkey\.exploit\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string20 = /hook\-infection_monkey\.network\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string21 = /hook\-infection_monkey\.post_breach\.actions\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string22 = /hook\-infection_monkey\.post_breach\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string23 = /hook\-infection_monkey\.ransomware\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string24 = /hook\-infection_monkey\.system_info\.collectors\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string25 = /hook\-pypsrp\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string26 = /HostExploiter\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string27 = /infection_monkey\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string28 = /linux_trap_command\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string29 = /mimikatz_cred_collector\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string30 = /Monkey\sIsland\sv.{0,1000}_windows\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string31 = /monkey.{0,1000}tunnel\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string32 = /monkey\\infection_monkey/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string33 = /monkey_island\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string34 = /monkey32\.exe\s/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string35 = /monkey64\.exe\s/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string36 = /monkey\-linux\-32/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string37 = /monkey\-linux\-64/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string38 = /monkey\-windows\-32\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string39 = /monkey\-windows\-64\.exe/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string40 = /post_breach_handler\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string41 = /pypykatz_handler\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string42 = /ransomware_config\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string43 = /ransomware_payload\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string44 = /remote_shell\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string45 = /run_server\.bat/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string46 = /setuid_setgid\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string47 = /shell_startup_files_modification\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string48 = /victim_host_generator\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string49 = /windows_credentials\.py/ nocase ascii wide

    condition:
        any of them
}
