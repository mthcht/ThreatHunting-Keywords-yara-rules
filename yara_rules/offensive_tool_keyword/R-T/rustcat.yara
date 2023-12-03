rule rustcat
{
    meta:
        description = "Detection patterns for the tool 'rustcat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rustcat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string1 = /.{0,1000}\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string2 = /.{0,1000}\/rcat\-v.{0,1000}\-win\-x86_64\.exe.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string3 = /.{0,1000}\/rustcat\/releases\/latest\/download\/.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string4 = /.{0,1000}\/src\/unixshell\.rs.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string5 = /.{0,1000}\\rcat\-v.{0,1000}\-win\-x86_64\.exe.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string6 = /.{0,1000}B473B9A4135DE247C6D76510B40F63F8F1E5A2AB.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string7 = /.{0,1000}blackarch\/tree\/master\/packages\/rustcat.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string8 = /.{0,1000}pacman\s\-S\srustcat.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string9 = /.{0,1000}rcan\slisten\s\-ib\s.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string10 = /.{0,1000}rcat\sc\s\-s\sbash\s.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string11 = /.{0,1000}rcat\sconnect\s\-s\sbash.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string12 = /.{0,1000}rcat\slisten\s55660.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string13 = /.{0,1000}rcat\slisten\s\-ie\s.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string14 = /.{0,1000}rcat\slisten\s\-l\s.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string15 = /.{0,1000}rcat\-v3\..{0,1000}darwin\-aarch64.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string16 = /.{0,1000}rcat\-v3\..{0,1000}\-darwin\-x86_64.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string17 = /.{0,1000}rcat\-v3\..{0,1000}\-linux\-x86_64.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string18 = /.{0,1000}rustcat\-3\.0\.0\.zip.{0,1000}/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string19 = /rcat\slisten\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
