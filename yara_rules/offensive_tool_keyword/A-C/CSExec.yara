rule csexec
{
    meta:
        description = "Detection patterns for the tool 'csexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string1 = /\/csexec\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string2 = /\/CSExec\.git/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string3 = /\/csexecsvc\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string4 = /\/csexecsvc\-net35\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string5 = /\/csexecsvc\-net40\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string6 = /\/csexecsvc\-net45\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string7 = /\\\\.{0,1000}\\pipe\\psexecsvc/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string8 = /\\csexec\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string9 = /\\csexecsvc\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string10 = /\\csexecsvc\-net35\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string11 = /\\csexecsvc\-net40\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string12 = /\\csexecsvc\-net45\.exe/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string13 = /\>csexec\</ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string14 = /\>csexecsvc\</ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string15 = /41A90A6A\-F9ED\-4A2F\-8448\-D544EC1FD753/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string16 = /41A90A6A\-F9ED\-4A2F\-8448\-D544EC1FD754/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string17 = /41A90A6A\-F9ED\-4A2F\-8448\-D544EC1FD755/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string18 = /58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string19 = /64fc0afc72a37b1071482e9c4725cd35fa2b974c6903cd01124ed7fe9d2c8e27/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string20 = /6d11a3d59602508d435fc3cabba737d7b5d710e2b56b7623e903e59ac3d3f287/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string21 = /73fb2d477ece754ce6ad9239126b69f9dc3dfc95775ef0714a4df26ee7ac4352/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string22 = /F3037587\-1A3B\-41F1\-AA71\-B026EFDB2A35/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string23 = /F3037587\-1A3B\-41F1\-AA71\-B026EFDB2A40/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string24 = /F3037587\-1A3B\-41F1\-AA71\-B026EFDB2A45/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string25 = /malcomvetter\/CSExec/ nocase ascii wide
        // Description: An implementation of PSExec in C#
        // Reference: https://github.com/malcomvetter/CSExec
        $string26 = /This\sis\ssimilar\sto\spsexec\s\-s\s\\/ nocase ascii wide

    condition:
        any of them
}
