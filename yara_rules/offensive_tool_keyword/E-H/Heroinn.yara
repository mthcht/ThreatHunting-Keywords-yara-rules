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
        $string1 = /.{0,1000}\/Heroinn\/.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string2 = /.{0,1000}\/shell\/shell_port\..{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string3 = /.{0,1000}0x9999997B3deF7b69c09D7a9CA65E5242fb04a764.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string4 = /.{0,1000}1HeroYcNYMhjsq8RYCx1stSaRZnQd9B9Eq.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string5 = /.{0,1000}b23r0\/Heroinn.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string6 = /.{0,1000}Heroinn\sFTP.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string7 = /.{0,1000}heroinn_client.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string8 = /.{0,1000}heroinn_core.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string9 = /.{0,1000}heroinn_ftp.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string10 = /.{0,1000}heroinn_shell.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string11 = /.{0,1000}heroinn_util.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string12 = /.{0,1000}HeroinnApp.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string13 = /.{0,1000}HeroinnProtocol.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string14 = /.{0,1000}HeroinnServerCommand.{0,1000}/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string15 = /.{0,1000}th3rd\/heroinn.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
