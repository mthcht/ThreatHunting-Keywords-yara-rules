rule Invoke_TmpDavFS
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TmpDavFS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TmpDavFS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Memory Backed Powershell WebDav Server - Creates a memory backed webdav server using powershell that can be mounted as a filesystem. Note: Mounting the remote filesystem on windows implies local caching of accessed files in the C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV system directory.
        // Reference: https://github.com/p3nt4/Invoke-TmpDavFS
        $string1 = /Invoke\-TmpDavFS/ nocase ascii wide

    condition:
        any of them
}
