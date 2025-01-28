rule LOLSpoof
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string1 = "# Find LOLBin and reconstruct commandline" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string2 = /\/lolbin\.exe/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string3 = /\/LOLSpoof\.git/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string4 = /\/LOLSpoof\.nim/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string5 = "/LOLSpoof/releases/download/" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string6 = /\[LOLSpoof\]\s\>\s/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string7 = /\\lolbin\.exe/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string8 = /\\LOLSpoof\.nim/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string9 = /\\LOLSpoof\\/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string10 = "159766fade72711fc8b28004ec1f2088bb837852029f1e79446d728728c235ef" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string11 = "8310f53135ddcc2e6b9fd6ca2aca3662f61dc1b5fb2b2510fa762e5862afcf94" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string12 = "84f94c746a47d8bee6663a57051e15ce80f6847dc66733c31b1d793301814fcb" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string13 = "An interactive shell to spoof some LOLBins" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string14 = "Could not spoof binary: " nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string15 = "f8d85258f9c717fb629942c43b2218c96800252c3da18cbbc11839f790acc452" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string16 = "itaymigdal/LOLSpoof" nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string17 = /lolbin\.exe\s/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string18 = /LOLSpoof\.exe/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
