rule ZipExec
{
    meta:
        description = "Detection patterns for the tool 'ZipExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZipExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string1 = /\/ZipExec\s\-/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string2 = /\/ZipExec\.git/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string3 = /\/ZipExec\@latest/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string4 = /\\ZipExec\s\-/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string5 = /\\ZipExec\.exe/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string6 = /\\ZipExec\.go/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string7 = /b206d36ab4eb52419e27ca315cc9151e86eb31513ab6aa28fe8879141ef746bb/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string8 = /build\sZipExec\.go/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string9 = /calc\.zip\s\/pass\:xOVTzio/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string10 = /Tylous\/ZipExec/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string11 = /ZipExec\/Cryptor/ nocase ascii wide
        // Description: A unique technique to execute binaries from a password protected zip
        // Reference: https://github.com/Tylous/ZipExec
        $string12 = /ZipExec\/Loader/ nocase ascii wide

    condition:
        any of them
}
