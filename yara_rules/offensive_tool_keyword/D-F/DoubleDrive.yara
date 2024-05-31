rule DoubleDrive
{
    meta:
        description = "Detection patterns for the tool 'DoubleDrive' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoubleDrive"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string1 = /\s\-\-command\-uac\-bypass/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string2 = /\sendpoint_takeover\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string3 = /\sfollow_attacker_commands\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string4 = /\sgoogle_drive_doubledrive\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string5 = /\sRANSOM_NOTE\.txt/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string6 = /\s\-\-ransom\-note\-name\s/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string7 = /\s\-\-remote\-ransomware/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string8 = /\s\-\-sharepoint\-replacement\-exe\-path\s/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string9 = /\s\-\-temp\-email\s\-\-target\-paths\s/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string10 = /\svictim_info_key\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string11 = /\"PAY\sME\sMONEY\"/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string12 = /\"RANSOM_NOTE\.txt\"/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string13 = /\/DoubleDrive\.git/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string14 = /\/DoubleDrive\-main\.zip/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string15 = /\/endpoint_takeover\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string16 = /\/follow_attacker_commands\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string17 = /\/google_drive_doubledrive\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string18 = /\/victim_info_key\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string19 = /\\DoubleDrive\-main\.zip/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string20 = /\\endpoint_takeover\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string21 = /\\follow_attacker_commands\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string22 = /\\google_drive_doubledrive\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string23 = /\\RANSOM_NOTE\.txt/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string24 = /\\victim_info_key\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string25 = /055d93807dbb92adac4bfd63349ac634e7a214712115656f00d9a1750d98da52/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string26 = /4d7424482e96e9326182ad86bbe68a0f7b9da63d7508552649f05a18848d4bad/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string27 = /5eb8024e00c244de2646f2b338be02e7a6475637fd04894a3e13d37783b0d693/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string28 = /b310173eac2770b78f821900614fc900502e4cbe506daa55cd1baae3f22fa4cf/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string29 = /cloud_drive_ransomware\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string30 = /doubledrive\.cloud_drive\.google_drive\.google_drive/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string31 = /doubledrive\.cloud_ransomware/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string32 = /doubledrive\.endpoint_takeover_utils/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string33 = /eb2bcc1bc9b6802b3869f6343b0fcbe72f3d1642abbc34e0758122e6510c2f4a/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string34 = /endpoint_takeover\.exe/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string35 = /f3b57e4b17458688b689824705327c1e854a796a4e027b6e34855627e79454c0/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string36 = /follow_attacker_commands\.exe/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string37 = /follow_attacker_commands\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string38 = /google_drive_doubledrive\.exe/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string39 = /google_drive_ransomware\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string40 = /https\:\/\/api\.onedrive\.com\/v1\.0\/drives\/me\/items\/root\:\{onedrive_file_path\}\:\/oneDrive\.createUploadSession/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string41 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getDomainList/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string42 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getMessages\&login\=/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string43 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=readMessage\&login\=/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string44 = /onedrive_doubledrive\.exe/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string45 = /onedrive_doubledrive\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string46 = /onedrive_ransomware\.py/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string47 = /OneDriveRansomware\(CloudDriveRansomware\)/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string48 = /SafeBreach\-Labs\/DoubleDrive/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string49 = /save\sthe\sFernet\sencryption\/decryption\skey\s/ nocase ascii wide
        // Description: A fully-undetectable ransomware that utilizes OneDrive & Google Drive to encrypt target local files
        // Reference: https://github.com/SafeBreach-Labs/DoubleDrive
        $string50 = /vssadmin\sdelete\sshadows\s\/all\s\/quiet/ nocase ascii wide

    condition:
        any of them
}
