rule MaccaroniC2
{
    meta:
        description = "Detection patterns for the tool 'MaccaroniC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaccaroniC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string1 = /\/asyncssh_server\.py/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string2 = "/MaccaroniC2" nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string3 = /\\MaccaroniC2/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string4 = /127\.0\.0\.1\:8022/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string5 = /127\.0\.0\.1\:9050/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string6 = /asyncssh_commander\.py\s/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string7 = /asyncssh_commander\.py/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string8 = "localhost:8022" nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string9 = /MaccaroniC2\.git/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string10 = /socks5h\:\/\/127\.0\.0\.1\:9050/ nocase ascii wide

    condition:
        any of them
}
