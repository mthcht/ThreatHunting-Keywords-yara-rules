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
        $string4 = "/HRShell/" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string5 = "/meterpreter/reverse_tcp" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string6 = /\/shellcodes\/utils\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string7 = "chrispetrou/HRShell" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string8 = "exploit -j -z" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string9 = "from shellcodes import " nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string10 = "history_cmd" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string11 = /HRShell.{0,1000}client\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string12 = /HRShell.{0,1000}server\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string13 = "inject shellcode" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string14 = "set shellcode " nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string15 = "set_shellcode" nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string16 = /shellcode1\s\+\=\sb/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string17 = "set shellcode " nocase ascii wide

    condition:
        any of them
}
