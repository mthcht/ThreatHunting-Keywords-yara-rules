rule rsg
{
    meta:
        description = "Detection patterns for the tool 'rsg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string1 = " nc -n -v -l -s "
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string2 = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\./ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string3 = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string4 = "/bin/sh -i <&3 >&3 2>&3"
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string5 = "/usr/local/bin/rsg"
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string6 = "64cd8640e2b53358f8fbafbcbded6db53e1acd49fe4ccc8196c8ed17c551bc70" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string7 = "b3804cac36175125199ddd8f6840749ead5c723d9641670d244d0a487fcf555c" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string8 = "ebdac49d15f37cc60cb5e755b10743512ececf134126e0ac4a024cb1149ae76f" nocase ascii wide
        // Description: A tool to generate various ways to do a reverse shell
        // Reference: https://github.com/mthbernardes/rsg
        $string9 = /mthbernardes.{0,1000}rsg/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string10 = "mthbernardes/rsg" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string11 = "nc -c /bin/sh "
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string12 = /php\s\-r\s.{0,1000}fsockopen.{0,1000}exec\(.{0,1000}\/bin\/sh/
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string13 = /powershell\s\-nop\s\-c\s\\"\\"\$client\s\=\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string14 = /ruby\s\-rsocket\s\-e\s\'.{0,1000}\=TCPSocket\.new\(/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string15 = /socat\.exe\s\-d\s\-d\sTCP4\:/ nocase ascii wide

    condition:
        any of them
}
