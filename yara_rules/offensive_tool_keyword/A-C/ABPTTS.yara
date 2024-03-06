rule ABPTTS
{
    meta:
        description = "Detection patterns for the tool 'ABPTTS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ABPTTS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string1 = /\/ABPTTS\.git/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string2 = /\\ABPTTS\-master/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string3 = /\=\=\=\[\[\[\sA\sBlack\sPath\sToward\sThe\sSun\s\]\]\]\=\=\=/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string4 = /63688c4f211155c76f2948ba21ebaf83/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string5 = /abpttsclient\.py/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string6 = /ABPTTSClient\-log\.txt/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string7 = /abpttsfactory\.py/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string8 = /Building\sABPTTS\sconfiguration\s/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string9 = /nccgroup\/ABPTTS/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string10 = /tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq/ nocase ascii wide

    condition:
        any of them
}
