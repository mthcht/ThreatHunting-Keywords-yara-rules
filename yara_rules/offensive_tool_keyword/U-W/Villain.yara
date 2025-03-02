rule Villain
{
    meta:
        description = "Detection patterns for the tool 'Villain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Villain"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string1 = " --file-smuggler-port "
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string2 = " --hoax-port "
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string3 = " --netcat-port "
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string4 = /\.villain_core/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string5 = /\/hoaxshell\/.{0,1000}\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string6 = "/t3l3machus/Villain"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string7 = /\/villain\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string8 = /\\hoaxshell\\.{0,1000}\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string9 = /awk_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string10 = /bash_read_line_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string11 = "cmdinspector OFF"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string12 = "cmdinspector ON"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string13 = "conptyshell "
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string14 = "eRv6yTYhShell"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string15 = "File_Smuggler_Http_Handler"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string16 = "generate payload="
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string17 = "Invoke-ConPtyShell"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string18 = "list_backdoors"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string19 = "obfuscate_cmdlet"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string20 = /perl_no_sh_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string21 = /php_passthru_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string22 = /php_popen_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string23 = /php_proc_open_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string24 = /powershell_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string25 = /powershell_reverse_tcp_v2\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string26 = "proxy_cmd_for_exec_by_sibling"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string27 = /python3_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string28 = /python3_reverse_tcp_v2\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string29 = /ruby_no_sh_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string30 = /ruby_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string31 = "SpawneRv6yTYhShell"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string32 = /Villain\.git/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string33 = "Villain/Core"
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string34 = /villain_core\.py/

    condition:
        any of them
}
