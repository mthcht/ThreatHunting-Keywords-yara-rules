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
        $string1 = /.{0,1000}\s\-\-file\-smuggler\-port\s.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string2 = /.{0,1000}\s\-\-hoax\-port\s.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string3 = /.{0,1000}\s\-\-netcat\-port\s.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string4 = /.{0,1000}\.villain_core.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string5 = /.{0,1000}\/hoaxshell\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string6 = /.{0,1000}\/t3l3machus\/Villain.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string7 = /.{0,1000}\\hoaxshell\\.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string8 = /.{0,1000}awk_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string9 = /.{0,1000}bash_read_line_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string10 = /.{0,1000}cmdinspector\sOFF.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string11 = /.{0,1000}cmdinspector\sON.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string12 = /.{0,1000}conptyshell\s.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string13 = /.{0,1000}eRv6yTYhShell.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string14 = /.{0,1000}File_Smuggler_Http_Handler.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string15 = /.{0,1000}generate\spayload\=.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string16 = /.{0,1000}Invoke\-ConPtyShell.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string17 = /.{0,1000}list_backdoors.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string18 = /.{0,1000}obfuscate_cmdlet.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string19 = /.{0,1000}perl_no_sh_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string20 = /.{0,1000}php_passthru_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string21 = /.{0,1000}php_popen_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string22 = /.{0,1000}php_proc_open_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string23 = /.{0,1000}powershell_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string24 = /.{0,1000}powershell_reverse_tcp_v2\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string25 = /.{0,1000}proxy_cmd_for_exec_by_sibling.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string26 = /.{0,1000}python3_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string27 = /.{0,1000}python3_reverse_tcp_v2\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string28 = /.{0,1000}ruby_no_sh_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string29 = /.{0,1000}ruby_reverse_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string30 = /.{0,1000}SpawneRv6yTYhShell.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string31 = /.{0,1000}Villain\.git.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string32 = /.{0,1000}villain\.py.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string33 = /.{0,1000}Villain\/Core.{0,1000}/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string34 = /.{0,1000}villain_core\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
