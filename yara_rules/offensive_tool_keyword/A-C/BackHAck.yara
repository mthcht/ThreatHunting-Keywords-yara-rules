rule BackHAck
{
    meta:
        description = "Detection patterns for the tool 'BackHAck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackHAck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string1 = /\sbackhack\.py/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string2 = /\/BackHAck\.git/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string3 = /\/backhack\.py/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string4 = /\\backhack\.py/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string5 = "48c4df943d19bc547c6cab3a3c802dbcf13af3b7880b3977aef74f452c831a95"
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string6 = "93df885410ce2b2ea1428127077bcf574e56838ce8ccf4ea410a1f120544f9b8"
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string7 = "AngelSecurityTeam/BackHAck"
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string8 = "AngelSecurityTeam-BackdoorLinux"
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string9 = /AngelSecurityTeam\-BackdoorWindows\.exe/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string10 = /AngelSecurityTeam\-BackdoorWindows\.exe/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string11 = /curl\s\-s\s\-N\shttp\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string12 = /https\:\/\/bin\.equinox\.io\/c\/4VmDzA7iaHb\//
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string13 = /ngrok\-stable\-linux\-arm\.zip/
        // Description: Backdoor Generator with C2 server - Linux & Windows - FUD AV .py .exe
        // Reference: https://github.com/AngelSecurityTeam/BackHAck
        $string14 = /python3\s\-m\shttp\.server\s80\s\>\s\.server\s2\>\s\/dev\/null/

    condition:
        any of them
}
