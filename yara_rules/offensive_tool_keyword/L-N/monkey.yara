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
        $string1 = /.{0,1000}\.\/monkey\.sh.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string2 = /.{0,1000}\/infection_monkey\/.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string3 = /.{0,1000}\/log4shell\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string4 = /.{0,1000}\/monkey\.py/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string5 = /.{0,1000}\/monkey_island\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string6 = /.{0,1000}\/shellshock\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string7 = /.{0,1000}\/smbexec\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string8 = /.{0,1000}\/timestomping\.ps1.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string9 = /.{0,1000}\/trap_command\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string10 = /.{0,1000}\/web_rce\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string11 = /.{0,1000}\/zerologon\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string12 = /.{0,1000}\\monkey\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string13 = /.{0,1000}\\monkey32\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string14 = /.{0,1000}\\monkey64\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string15 = /.{0,1000}clear_command_history\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string16 = /.{0,1000}communicate_as_backdoor_user\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string17 = /.{0,1000}dump_secrets\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string18 = /.{0,1000}guardicore\/monkey.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string19 = /.{0,1000}hook\-infection_monkey\.exploit\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string20 = /.{0,1000}hook\-infection_monkey\.network\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string21 = /.{0,1000}hook\-infection_monkey\.post_breach\.actions\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string22 = /.{0,1000}hook\-infection_monkey\.post_breach\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string23 = /.{0,1000}hook\-infection_monkey\.ransomware\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string24 = /.{0,1000}hook\-infection_monkey\.system_info\.collectors\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string25 = /.{0,1000}hook\-pypsrp\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string26 = /.{0,1000}HostExploiter\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string27 = /.{0,1000}infection_monkey\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string28 = /.{0,1000}linux_trap_command\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string29 = /.{0,1000}mimikatz_cred_collector\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string30 = /.{0,1000}Monkey\sIsland\sv.{0,1000}_windows\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string31 = /.{0,1000}monkey.{0,1000}tunnel\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string32 = /.{0,1000}monkey\\infection_monkey.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string33 = /.{0,1000}monkey_island\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string34 = /.{0,1000}monkey32\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string35 = /.{0,1000}monkey64\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string36 = /.{0,1000}monkey\-linux\-32.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string37 = /.{0,1000}monkey\-linux\-64.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string38 = /.{0,1000}monkey\-windows\-32\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string39 = /.{0,1000}monkey\-windows\-64\.exe.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string40 = /.{0,1000}post_breach_handler\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string41 = /.{0,1000}pypykatz_handler\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string42 = /.{0,1000}ransomware_config\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string43 = /.{0,1000}ransomware_payload\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string44 = /.{0,1000}remote_shell\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string45 = /.{0,1000}run_server\.bat/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string46 = /.{0,1000}setuid_setgid\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string47 = /.{0,1000}shell_startup_files_modification\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string48 = /.{0,1000}victim_host_generator\.py.{0,1000}/ nocase ascii wide
        // Description: Infection Monkey - An automated pentest tool
        // Reference: https://github.com/guardicore/monkey
        $string49 = /.{0,1000}windows_credentials\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
