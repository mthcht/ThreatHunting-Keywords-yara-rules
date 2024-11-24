rule WSAAcceptBackdoor
{
    meta:
        description = "Detection patterns for the tool 'WSAAcceptBackdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSAAcceptBackdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string1 = /\/WSAAcceptBackdoor\.git/ nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string2 = /\\WSAAcceptBackdoor\./ nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string3 = /\\WSAAcceptBackdoor\-main/ nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string4 = "16edb60cec97590d754e99e2eb719bbc990d71dcf1bda7c8eebf3b517574846d" nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string5 = "811683b1-e01c-4ef8-82d1-aa08293d3e7c" nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string6 = "define BACKDOOR_PORT " nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string7 = "EgeBalci/WSAAcceptBackdoor" nocase ascii wide
        // Description: Winsock accept() Backdoor Implant
        // Reference: https://github.com/EgeBalci/WSAAcceptBackdoor
        $string8 = /WSAAcceptBackdoor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
