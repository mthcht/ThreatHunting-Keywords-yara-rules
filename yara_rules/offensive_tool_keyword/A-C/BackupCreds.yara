rule BackupCreds
{
    meta:
        description = "Detection patterns for the tool 'BackupCreds' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupCreds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string1 = /\sbackupcreds\.exe/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string2 = /\/backupcreds\.exe/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string3 = /\/BackupCreds\.git/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string4 = /\[\!\]\sCredBackupCredentials\(/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string5 = /\\BackupCreds\.csproj/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string6 = /\\backupcreds\.exe/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string7 = /\\backupcreds\.sln/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string8 = /\\backupcreds\\Program\.cs/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string9 = /\\BackupCreds\-main/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string10 = /\]\sEnjoy\syour\screds\!\sReverting\sto\sself/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string11 = /7943C5FF\-C219\-4E0B\-992E\-0ECDEB2681F3/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string12 = /leftp\/BackupCreds/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string13 = /namespace\sBackupCreds/ nocase ascii wide
        // Description: A C# implementation of dumping credentials from Windows Credential Manager
        // Reference: https://github.com/leftp/BackupCreds
        $string14 = /using\sstatic\sBackupCreds\.Interop/ nocase ascii wide

    condition:
        any of them
}
