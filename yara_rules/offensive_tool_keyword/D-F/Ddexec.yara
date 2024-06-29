rule Ddexec
{
    meta:
        description = "Detection patterns for the tool 'Ddexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ddexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string1 = /\sbash\sddexec\.sh/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string2 = /\sddexec\.sh\s/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string3 = /\sddsc\.sh\s\-x/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string4 = /\szsh\sddexec\.sh/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string5 = /\/DDexec\.git/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string6 = /\/ddexec\.sh/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string7 = /\/ddsc\.sh\s/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string8 = /4109aabda29898f764177befbe6967500dd724e511317a8232a046c91502b38f/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string9 = /955201aaf535183bd7a881278fbaab7a16f742c150ff44e1d7ab0325c0c03baf/ nocase ascii wide
        // Description: A technique to run binaries filelessly and stealthily on Linux by "overwriting" the shell's process with another.
        // Reference: https://github.com/arget13/DDexec
        $string10 = /arget13\/DDexec/ nocase ascii wide

    condition:
        any of them
}
