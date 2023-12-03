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
        $string1 = /.{0,1000}\/asyncssh_server\.py.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string2 = /.{0,1000}\/MaccaroniC2.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string3 = /.{0,1000}\\MaccaroniC2.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string4 = /.{0,1000}127\.0\.0\.1:8022.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string5 = /.{0,1000}127\.0\.0\.1:9050.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string6 = /.{0,1000}asyncssh_commander\.py\s.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string7 = /.{0,1000}asyncssh_commander\.py.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string8 = /.{0,1000}localhost:8022.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string9 = /.{0,1000}MaccaroniC2\.git.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string10 = /.{0,1000}socks5h:\/\/127\.0\.0\.1:9050.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
