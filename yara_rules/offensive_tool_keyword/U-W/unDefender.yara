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
        $string1 = /.{0,1000}\sunDefender\.exe.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string2 = /.{0,1000}\/unDefender\.exe.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string3 = /.{0,1000}\/unDefender\.git.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string4 = /.{0,1000}\\unDefender\.exe.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string5 = /.{0,1000}APTortellini\/unDefender.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string6 = /.{0,1000}copy\s.{0,1000}\\legit\.sys\s.{0,1000}Windows\\System32\\Drivers\\.{0,1000}\.sys.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string7 = /.{0,1000}ImpersonateAndUnload\.cpp.{0,1000}/ nocase ascii wide
        // Description: Killing your preferred antimalware by abusing native symbolic links and NT paths.
        // Reference: https://github.com/APTortellini/unDefender
        $string8 = /.{0,1000}unDefender\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
