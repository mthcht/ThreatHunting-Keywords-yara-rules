rule ShellPwnsh
{
    meta:
        description = "Detection patterns for the tool 'ShellPwnsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellPwnsh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string1 = /\.\/ShellPwnsh/
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string2 = /\/ShellPwnsh\.git/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string3 = /\\ShellPwnsh\-main/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string4 = "32c3b62e05eb08f482b00ca28bca9b43d743048f287e9b42193df91d6ddcd09a" nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string5 = "7e40488e6ce8545eccdcfd13124e609ff74c50a9ce89bc88b9b2b50862efda9c" nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string6 = "9374f1f361c8c664f4527cc9e43e277fddab0bfc032e254fec9b22405210f808" nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string7 = "BlackShell256/ShellPwnsh" nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string8 = /FUD\sPayload\sGenerator\sby\sBlack\$hell256/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string9 = /Generador\sde\sPayloads\sFUD\sby\sBlack\$hell256/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string10 = /ShellPwnsh\.exe/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string11 = /ShellPwnsh\.go/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string12 = /System\.Net\.\$\(\[Text\.Encoding\]\:\:Unicode\.GetString\(\[Convert\]\:\:FromBase64String\(/ nocase ascii wide
        // Description: Reverse Shell in Golang and PowerShell Fud
        // Reference: https://github.com/BlackShell256/ShellPwnsh
        $string13 = /\'UwBvAGM\'\;\s\$xd\s\=\s\'AawBlA\'/ nocase ascii wide

    condition:
        any of them
}
