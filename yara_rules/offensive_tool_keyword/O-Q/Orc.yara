rule Orc
{
    meta:
        description = "Detection patterns for the tool 'Orc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Orc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string1 = /\smemexec\.pl/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string2 = /\smemexec\.py/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string3 = "#god bless you, NSA's autorootkit"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string4 = /\/memexec\.pl/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string5 = /\/memexec\.py/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string6 = /\/suspect\/master\/suspect\.sh/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string7 = "= Welcome to Orc Shell ="
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string8 = "50084b701b0463d1698211f2d0427c3eb6322be963c46cf9a4eb39e01a94cddc"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string9 = "810b9f7c517f7f00516340661ecaf5610b89ea25ff5261964abe067a40c474c2"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string10 = "find /tmp/ -executable -type f 2>/dev/null"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string11 = "find /var/tmp -executable -type f 2>/dev/null"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string12 = /getent\spasswd\s\|\sgrep\ssh\$\s\|\scut\s\-d\s/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string13 = /linux\-exploit\-suggester\.sh/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string14 = "lsattr -a /usr/bin/ /bin/ /sbin/ /usr/sbin/ 2>/dev/null"
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string15 = /orc_loadURL\s\'https\:\/\/gtfobins\.github\.io/
        // Description: Orc is a post-exploitation framework for Linux written in Bash
        // Reference: https://github.com/zMarch/Orc
        $string16 = "zMarch/Orc"

    condition:
        any of them
}
