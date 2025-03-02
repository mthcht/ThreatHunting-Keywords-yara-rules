rule HardHatC2
{
    meta:
        description = "Detection patterns for the tool 'HardHatC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HardHatC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string1 = "/Donut_Linux"
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string2 = "/Donut_Windows" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string3 = "196B8469-F798-4ECC-9A77-C1CAB5BF6EAE" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string4 = "5010BEE8-0944-4655-987F-AB3BB376E774" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string5 = "62B6EF3C-3180-4730-A2CE-82D27C43A5B2" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string6 = "920D97B7-8091-4224-8CF7-D9D72A64A7FE" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string7 = "B1865FC0-5605-4587-9FCB-8B9DF6B5C6B1" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string8 = /C2TaskMessage\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string9 = /Confuser\.CLI\.Exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string10 = /CreateC2Dialog\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string11 = /EditC2Dialog\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string12 = /EncodeShellcode\(/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string13 = /Engineer_super\.exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string14 = "HardHatC2" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string15 = /hardhatc2\.com/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string16 = "HardHatC2Client" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string17 = /http.{0,1000}127\.0\.0\.1\:21802/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string18 = /http.{0,1000}127\.0\.0\.1\:5000/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string19 = /http.{0,1000}127\.0\.0\.1\:5096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string20 = /http.{0,1000}127\.0\.0\.1\:7096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string21 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string22 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string23 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string24 = /http.{0,1000}127\.0\.0\.1\:9631/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string25 = /http.{0,1000}localhost\:21802/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string26 = /http.{0,1000}localhost\:5000/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string27 = /http.{0,1000}localhost\:5096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string28 = /http.{0,1000}localhost\:7096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string29 = /http.{0,1000}localhost\:9631/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string30 = /inlineAssembly.{0,1000}\/execmethod/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string31 = /inlineDll.{0,1000}\/dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string32 = "InlineShellcode" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string33 = "jtee43gt-6543-2iur-9422-83r5w27hgzaq" nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string34 = /Patch\-AMSI\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string35 = /Patch\-ETW\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string36 = /powerkatz\.dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string37 = /spawnto\s.{0,1000}\/path\s/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string38 = /unmanagedPowershell\s.{0,1000}\/command/ nocase ascii wide

    condition:
        any of them
}
