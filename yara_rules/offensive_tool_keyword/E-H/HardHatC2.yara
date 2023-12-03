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
        $string1 = /.{0,1000}\/Donut_Linux.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string2 = /.{0,1000}\/Donut_Windows.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string3 = /.{0,1000}C2TaskMessage\..{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string4 = /.{0,1000}Confuser\.CLI\.Exe.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string5 = /.{0,1000}CreateC2Dialog\..{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string6 = /.{0,1000}EditC2Dialog\..{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string7 = /.{0,1000}EncodeShellcode\(.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string8 = /.{0,1000}Engineer_super\.exe.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string9 = /.{0,1000}HardHatC2.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string10 = /.{0,1000}hardhatc2\.com.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string11 = /.{0,1000}HardHatC2Client.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string12 = /.{0,1000}http.{0,1000}127\.0\.0\.1:21802.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string13 = /.{0,1000}http.{0,1000}127\.0\.0\.1:5000.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string14 = /.{0,1000}http.{0,1000}127\.0\.0\.1:5096.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string15 = /.{0,1000}http.{0,1000}127\.0\.0\.1:7096.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string16 = /.{0,1000}http.{0,1000}127\.0\.0\.1:8080\/.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string17 = /.{0,1000}http.{0,1000}127\.0\.0\.1:8080\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string18 = /.{0,1000}http.{0,1000}127\.0\.0\.1:8080\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string19 = /.{0,1000}http.{0,1000}127\.0\.0\.1:9631.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string20 = /.{0,1000}http.{0,1000}localhost:21802.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string21 = /.{0,1000}http.{0,1000}localhost:5000.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string22 = /.{0,1000}http.{0,1000}localhost:5096.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string23 = /.{0,1000}http.{0,1000}localhost:7096.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string24 = /.{0,1000}http.{0,1000}localhost:9631.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string25 = /.{0,1000}inlineAssembly.{0,1000}\/execmethod.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string26 = /.{0,1000}inlineDll.{0,1000}\/dll.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string27 = /.{0,1000}InlineShellcode.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string28 = /.{0,1000}jtee43gt\-6543\-2iur\-9422\-83r5w27hgzaq.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string29 = /.{0,1000}Patch\-AMSI\..{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string30 = /.{0,1000}Patch\-ETW\..{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string31 = /.{0,1000}powerkatz\.dll.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string32 = /.{0,1000}spawnto\s.{0,1000}\/path\s.{0,1000}/ nocase ascii wide
        // Description: A C# Command & Control framework
        // Reference: https://github.com/DragoQCC/HardHatC2
        $string33 = /.{0,1000}unmanagedPowershell\s.{0,1000}\/command.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
