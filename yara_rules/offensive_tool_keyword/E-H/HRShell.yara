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
        $string1 = /.{0,1000}\sclient\.py\s\-s\shttp.{0,1000}:5000\s\-\-cert\s\/.{0,1000}\.pem.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string2 = /.{0,1000}\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,1000}pem\s\-\-key\s\/.{0,1000}\.pem.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string3 = /.{0,1000}\/HRShell\.git.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string4 = /.{0,1000}\/HRShell\/.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string5 = /.{0,1000}\/meterpreter\/reverse_tcp.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string6 = /.{0,1000}\/shellcodes\/utils\.py.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string7 = /.{0,1000}chrispetrou\/HRShell.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string8 = /.{0,1000}clear_cmd/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string9 = /.{0,1000}from\sshellcodes\simport\s.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string10 = /.{0,1000}history_cmd/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string11 = /.{0,1000}HRShell.{0,1000}client\.py.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string12 = /.{0,1000}HRShell.{0,1000}server\.py.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string13 = /.{0,1000}inject\sshellcode.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string14 = /.{0,1000}set\sshellcode\s.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string15 = /.{0,1000}set_shellcode/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string16 = /.{0,1000}shellcode1\s\+\=\sb.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string17 = /exploit\s\-j\s\-z/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string18 = /set\sshellcode\s.{0,1000}/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string19 = /show\sshellcodes/ nocase ascii wide

    condition:
        any of them
}
