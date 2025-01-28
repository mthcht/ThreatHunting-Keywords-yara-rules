rule FileZilla
{
    meta:
        description = "Detection patterns for the tool 'FileZilla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FileZilla"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string1 = /\/FileZilla_.{0,1000}_sponsored\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string2 = /\/FileZilla_Server_.{0,1000}\.deb/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string3 = /\\FileZilla_.{0,1000}_sponsored\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string4 = /\\FILEZILLA_.{0,1000}_WIN64_SPONSO\-.{0,1000}\.pf/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string5 = /\\FileZilla_.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string6 = /\\FileZilla_Server_/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string7 = /\\Program\sFiles\\FileZilla\sFTP\sClient\\/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string8 = /\\Program\sFiles\\FileZilla\sServer/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string9 = /\\Software\\WOW6432Node\\FileZilla\sClient/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string10 = ">FileZilla FTP Client<" nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string11 = ">FileZilla Server<" nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string12 = /download\.filezilla\-project\.org/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string13 = /Software\\FileZilla/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string14 = "Win32/FileZilla_BundleInstaller" nocase ascii wide

    condition:
        any of them
}
