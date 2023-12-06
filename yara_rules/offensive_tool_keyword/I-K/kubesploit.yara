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
        $string1 = /\/kubesploit\.git/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string2 = /\/merlin\.dll/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string3 = /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\.exe/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string4 = /bin\/dll\/merlin\.c/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string5 = /c1090dbc\-f2f7\-4d90\-a241\-86e0c0217786/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string6 = /c2endpoint\.php/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string7 = /cmd\/merlinagent\// nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string8 = /cmd\/merlinagentdll\// nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string9 = /cyberark\/kubesploit/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string10 = /DisableRealtimeMonitoring\s\$true/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string11 = /html\/scripts\/merlin\.js/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string12 = /Invoke\-ADSBackdoor/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string13 = /Invoke\-Merlin\.ps1/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string14 = /Invoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string15 = /Joey\sis\sthe\sbest\shacker\sin\sHackers/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string16 = /kubeletAttack\.json/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string17 = /Kubesploit\sAgent/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string18 = /kubesploitAgent\-Darwin/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string19 = /kubesploitAgent\-Linux/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string20 = /kubesploit\-main/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string21 = /kubesploitServer\-Darwin/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string22 = /kubesploitServer\-Linux/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string23 = /M\.i\.m\.i\.k\.a\.t\.z/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string24 = /Merlin_v0\.1Beta\.zip/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string25 = /merlinAgent\.exe/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string26 = /merlinAgent\-Windows\-x64\.exe/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string27 = /MerlinCheatSheet\.pdf/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string28 = /merlinserver\.go/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string29 = /merlinserver_windows_x64\.exe/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string30 = /merlinServerLog\.txt/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string31 = /Password.{0,1000}Winter2017/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string32 = /Verified\sMerlin\sserver\s/ nocase ascii wide
        // Description: Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // Reference: https://github.com/cyberark/kubesploit
        $string33 = /xZF7fvaGD6p2yeLyf9i7O9gBBHk05B0u/ nocase ascii wide

    condition:
        any of them
}
