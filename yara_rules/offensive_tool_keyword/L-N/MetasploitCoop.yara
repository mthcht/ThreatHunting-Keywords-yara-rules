rule MetasploitCoop
{
    meta:
        description = "Detection patterns for the tool 'MetasploitCoop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MetasploitCoop"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string1 = " MetasploitCoop" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string2 = /\smsfws\.py\s/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string3 = "/metasploit-coop:" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string4 = /\/MetasploitCoop_0x727\.git/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string5 = /\/MetasploitCoop\-Backend\.git/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Frontend
        $string6 = /\/MetasploitCoop\-Frontend\.git/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string7 = "/metasploit-framework/" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string8 = /\/msfws\.py/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string9 = "/pymetasploit/" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string10 = /\[MetasploitCoop\-Backend\]/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string11 = /\[MetasploitCoop\-Frontend\]/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string12 = /\\\\system32\\\\msf\.sys/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string13 = /\\system32\\msf\.sys/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string14 = "0x727/MetasploitCoop_0x727" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string15 = "0x727/MetasploitCoop-Backend" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Frontend
        $string16 = "0x727/MetasploitCoop-Frontend" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string17 = "877d4290b0f991fcf2fb3e5f64916a2dfb844280010df806d28a94ad57f0de07" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string18 = "8915669ca2e25c835fbc5c022b3f1d62fab4569190e216a4b37a8d1e4f94208c" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string19 = "CREATE DATABASE homados" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop_0x727
        $string20 = /https\:\/\/127\.0\.0\.1\:60443/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string21 = "killme:qAuxiAwegDsZI" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string22 = /MIIEpAIBAAKCAQEAp4fWROz5dd1ylzYsMWYY6Y\+EBfPjvieE7EniddfMkA7ss47F/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string23 = "MSF_WS_JSON_RPC_API_TOKEN" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string24 = /payload\/pezor\.py/ nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string25 = "payload/windows/dllinject/bind_tcp_uuid" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string26 = "Starting Browser Autopwn with Adobe Flash-only BrowserExploitServer-based exploits" nocase ascii wide
        // Description: Post-exploitation collaboration platform based on MSF
        // Reference: https://github.com/0x727/MetasploitCoop-Backend
        $string27 = "starting the post exploitation with post exploitation modules" nocase ascii wide

    condition:
        any of them
}
