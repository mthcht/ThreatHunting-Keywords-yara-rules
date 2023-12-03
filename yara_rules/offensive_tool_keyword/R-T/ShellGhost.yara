rule ShellGhost
{
    meta:
        description = "Detection patterns for the tool 'ShellGhost' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGhost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string1 = /.{0,1000}\/ShellGhost\.git.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string2 = /.{0,1000}lem0nSec\/ShellGhost.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string3 = /.{0,1000}ShellGhost\.dll/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string4 = /.{0,1000}ShellGhost\.exe.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string5 = /.{0,1000}ShellGhost\.sln.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string6 = /.{0,1000}ShellGhost\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string7 = /.{0,1000}ShellGhost_mapping\.py.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string8 = /.{0,1000}ShellGhost\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string9 = /.{0,1000}src\/ShellGhost\.c.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
