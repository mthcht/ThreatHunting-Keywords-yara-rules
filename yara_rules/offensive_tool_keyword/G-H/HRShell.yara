rule HRShell
{
    meta:
        description = "Detection patterns for the tool 'HRShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HRShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string1 = /\sclient\.py\s\-s\shttp.{0,1000}\:5000\s\-\-cert\s\/.{0,1000}\.pem/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string2 = /\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,1000}pem\s\-\-key\s\/.{0,1000}\.pem/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string3 = /\/HRShell\.git/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string4 = /\/HRShell\// nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string5 = /\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string6 = /\/shellcodes\/utils\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string7 = /chrispetrou\/HRShell/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string8 = /clear_cmd/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string9 = /exploit\s\-j\s\-z/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string10 = /from\sshellcodes\simport\s/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string11 = /history_cmd/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string12 = /HRShell.{0,1000}client\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string13 = /HRShell.{0,1000}server\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string14 = /inject\sshellcode/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string15 = /set\sshellcode\s/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string16 = /set_shellcode/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string17 = /shellcode1\s\+\=\sb/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string18 = /set\sshellcode\s/ nocase ascii wide

    condition:
        any of them
}
