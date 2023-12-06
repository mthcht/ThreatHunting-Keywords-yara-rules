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
        $string1 = /\s\-\-file\-smuggler\-port\s/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string2 = /\s\-\-hoax\-port\s/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string3 = /\s\-\-netcat\-port\s/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string4 = /\.villain_core/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string5 = /\/hoaxshell\/.{0,1000}\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string6 = /\/t3l3machus\/Villain/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string7 = /\\hoaxshell\\.{0,1000}\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string8 = /awk_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string9 = /bash_read_line_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string10 = /cmdinspector\sOFF/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string11 = /cmdinspector\sON/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string12 = /conptyshell\s/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string13 = /eRv6yTYhShell/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string14 = /File_Smuggler_Http_Handler/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string15 = /generate\spayload\=/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string16 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string17 = /list_backdoors/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string18 = /obfuscate_cmdlet/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string19 = /perl_no_sh_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string20 = /php_passthru_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string21 = /php_popen_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string22 = /php_proc_open_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string23 = /powershell_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string24 = /powershell_reverse_tcp_v2\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string25 = /proxy_cmd_for_exec_by_sibling/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string26 = /python3_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string27 = /python3_reverse_tcp_v2\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string28 = /ruby_no_sh_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string29 = /ruby_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string30 = /SpawneRv6yTYhShell/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string31 = /Villain\.git/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string32 = /villain\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string33 = /Villain\/Core/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string34 = /villain_core\.py/ nocase ascii wide

    condition:
        any of them
}
