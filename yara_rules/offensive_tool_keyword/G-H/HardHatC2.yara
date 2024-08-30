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
        $string1 = /\/Donut_Linux/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string2 = /\/Donut_Windows/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string3 = /C2TaskMessage\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string4 = /Confuser\.CLI\.Exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string5 = /CreateC2Dialog\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string6 = /EditC2Dialog\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string7 = /EncodeShellcode\(/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string8 = /Engineer_super\.exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string9 = /HardHatC2/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string10 = /hardhatc2\.com/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string11 = /HardHatC2Client/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string12 = /http.{0,1000}127\.0\.0\.1\:21802/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string13 = /http.{0,1000}127\.0\.0\.1\:5000/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string14 = /http.{0,1000}127\.0\.0\.1\:5096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string15 = /http.{0,1000}127\.0\.0\.1\:7096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string16 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string17 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.exe/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string18 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string19 = /http.{0,1000}127\.0\.0\.1\:9631/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string20 = /http.{0,1000}localhost\:21802/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string21 = /http.{0,1000}localhost\:5000/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string22 = /http.{0,1000}localhost\:5096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string23 = /http.{0,1000}localhost\:7096/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string24 = /http.{0,1000}localhost\:9631/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string25 = /inlineAssembly.{0,1000}\/execmethod/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string26 = /inlineDll.{0,1000}\/dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string27 = /InlineShellcode/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string28 = /jtee43gt\-6543\-2iur\-9422\-83r5w27hgzaq/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string29 = /Patch\-AMSI\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string30 = /Patch\-ETW\./ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string31 = /powerkatz\.dll/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string32 = /spawnto\s.{0,1000}\/path\s/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string33 = /unmanagedPowershell\s.{0,1000}\/command/ nocase ascii wide

    condition:
        any of them
}
