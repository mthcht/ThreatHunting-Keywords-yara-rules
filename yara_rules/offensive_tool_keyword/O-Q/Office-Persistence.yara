rule Office_Persistence
{
    meta:
        description = "Detection patterns for the tool 'Office-Persistence' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Office-Persistence"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string1 = /\sOfficePersistence\.ps1/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string2 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\sexcel\.exe/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string3 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\spowerpoint\.exe/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string4 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\swinword\.exe/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string5 = /\$calcwllx64\s\=\s\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string6 = /\$calcwllx86\s\=\s\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string7 = /\/Office\-Persistence\.git/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string8 = /\/OfficePersistence\.ps1/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string9 = /\/Office\-Persistence\/master\/calc\.ppa/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string10 = /\\OfficePersistence\.ps1/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string11 = /3gstudent\/Office\-Persistence/ nocase ascii wide
        // Description: Use powershell to test Office-based persistence methods
        // Reference: https://github.com/3gstudent/Office-Persistence
        $string12 = /63a6bad64de560056ed496b6b7103056e4bdaf19f49011120997a5b87d141940/ nocase ascii wide

    condition:
        any of them
}
