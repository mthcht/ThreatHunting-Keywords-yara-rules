rule kubesploit
{
    meta:
        description = "Detection patterns for the tool 'kubesploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kubesploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string1 = /.{0,1000}\/kubesploit\.git.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string2 = /.{0,1000}\/merlin\.dll.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string3 = /.{0,1000}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\.exe.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string4 = /.{0,1000}bin\/dll\/merlin\.c.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string5 = /.{0,1000}c1090dbc\-f2f7\-4d90\-a241\-86e0c0217786.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string6 = /.{0,1000}c2endpoint\.php.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string7 = /.{0,1000}cmd\/merlinagent\/.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string8 = /.{0,1000}cmd\/merlinagentdll\/.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string9 = /.{0,1000}cyberark\/kubesploit.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string10 = /.{0,1000}DisableRealtimeMonitoring\s\$true.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string11 = /.{0,1000}html\/scripts\/merlin\.js.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string12 = /.{0,1000}Invoke\-ADSBackdoor.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string13 = /.{0,1000}Invoke\-Merlin\.ps1.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string14 = /.{0,1000}Invoke\-ReflectivePEInjection\.ps1.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string15 = /.{0,1000}Joey\sis\sthe\sbest\shacker\sin\sHackers.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string16 = /.{0,1000}kubeletAttack\.json.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string17 = /.{0,1000}Kubesploit\sAgent.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string18 = /.{0,1000}kubesploitAgent\-Darwin.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string19 = /.{0,1000}kubesploitAgent\-Linux.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string20 = /.{0,1000}kubesploit\-main.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string21 = /.{0,1000}kubesploitServer\-Darwin.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string22 = /.{0,1000}kubesploitServer\-Linux.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string23 = /.{0,1000}M\.i\.m\.i\.k\.a\.t\.z.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string24 = /.{0,1000}Merlin_v0\.1Beta\.zip.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string25 = /.{0,1000}merlinAgent\.exe.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string26 = /.{0,1000}merlinAgent\-Windows\-x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string27 = /.{0,1000}MerlinCheatSheet\.pdf.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string28 = /.{0,1000}merlinserver\.go.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string29 = /.{0,1000}merlinserver_windows_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string30 = /.{0,1000}merlinServerLog\.txt.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string31 = /.{0,1000}Password.{0,1000}Winter2017.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string32 = /.{0,1000}Verified\sMerlin\sserver\s.{0,1000}/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string33 = /.{0,1000}xZF7fvaGD6p2yeLyf9i7O9gBBHk05B0u.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
