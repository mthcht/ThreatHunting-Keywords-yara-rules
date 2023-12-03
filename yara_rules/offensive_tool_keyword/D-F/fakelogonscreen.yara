rule fakelogonscreen
{
    meta:
        description = "Detection patterns for the tool 'fakelogonscreen' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fakelogonscreen"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string1 = /.{0,1000}\/fakelogonscreen.{0,1000}/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string2 = /.{0,1000}fakelogonscreen\s.{0,1000}/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string3 = /.{0,1000}fakelogonscreen.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string4 = /.{0,1000}FakeLogonScreen\.csproj.{0,1000}/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string5 = /.{0,1000}fakelogonscreen\.exe.{0,1000}/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string6 = /.{0,1000}FakeLogonScreen\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
