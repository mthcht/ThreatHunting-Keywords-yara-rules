rule Heroinn
{
    meta:
        description = "Detection patterns for the tool 'Heroinn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Heroinn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string1 = /\/Heroinn\// nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string2 = /\/shell\/shell_port\./ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string3 = /0x9999997B3deF7b69c09D7a9CA65E5242fb04a764/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string4 = /1HeroYcNYMhjsq8RYCx1stSaRZnQd9B9Eq/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string5 = /b23r0\/Heroinn/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string6 = /Heroinn\sFTP/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string7 = /heroinn_client/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string8 = /heroinn_core/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string9 = /heroinn_ftp/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string10 = /heroinn_shell/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string11 = /heroinn_util/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string12 = /HeroinnApp/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string13 = /HeroinnProtocol/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string14 = /HeroinnServerCommand/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string15 = /th3rd\/heroinn/ nocase ascii wide

    condition:
        any of them
}
