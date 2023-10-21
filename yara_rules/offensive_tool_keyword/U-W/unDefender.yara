rule unDefender
{
    meta:
        description = "Detection patterns for the tool 'unDefender' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unDefender"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string1 = /\sunDefender\.exe/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string2 = /\/unDefender\.exe/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string3 = /\/unDefender\.git/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string4 = /\\unDefender\.exe/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string5 = /APTortellini\/unDefender/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string6 = /copy\s.*\\legit\.sys\s.*Windows\\System32\\Drivers\\.*\.sys/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string7 = /ImpersonateAndUnload\.cpp/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string8 = /unDefender\-master/ nocase ascii wide

    condition:
        any of them
}