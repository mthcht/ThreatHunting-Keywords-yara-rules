rule GraphRunner
{
    meta:
        description = "Detection patterns for the tool 'GraphRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string1 = /.{0,1000}\sCan\ssearch\sall\sTeams\smessages\sin\sall\schannels\sthat\sare\sreadable\sby\sthe\scurrent\suser.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string2 = /.{0,1000}\sClones\sa\ssecurity\sgroup\swhile\susing\san\sidentical\sname\sand\smember\slist\sbut\scan\sinject\sanother\suser\sas\swell.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string3 = /.{0,1000}\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sGraphRunner\sModule\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string4 = /.{0,1000}\sGraphRunner\.ps1.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string5 = /.{0,1000}\sImport\stokens\sfrom\sother\stools\sfor\suse\sin\sGraphRunner.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string6 = /.{0,1000}\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sPillage\sModules\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string7 = /.{0,1000}\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sRecon\s\&\sEnumeration\sModules\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string8 = /.{0,1000}\sSuccessful\sauthentication\.\sAccess\sand\srefresh\stokens\shave\sbeen\swritten\sto\sthe\sglobal\s\$apptokens\svariable\.\sTo\suse\sthem\swith\sother\sGraphRunner\smodules\suse\sthe\sTokens\sflag\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string9 = /.{0,1000}\sTest\sdifferent\sCLientID\'s\sagainst\sMSGraph\sto\sdetermine\spermissions.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string10 = /.{0,1000}\#\sPerform\sthe\sHTTP\sPOST\srequest\sto\ssearch\semails.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string11 = /.{0,1000}\/GraphRunner\.git.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string12 = /.{0,1000}\/GraphRunner\.ps1.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string13 = /.{0,1000}\/GraphRunner\-main.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string14 = /.{0,1000}\/interesting\-teamsmessages\.csv.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string15 = /.{0,1000}\/Passwords\.docx.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string16 = /.{0,1000}\[.{0,1000}\]\sAppending\saccess\stokens\sto\saccess_tokens\.txt.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string17 = /.{0,1000}\[.{0,1000}\]\sChecking\saccess\sto\smailboxes\sfor\seach\semail\saddress\?.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string18 = /.{0,1000}\\\"\-SecureString\\\"\sOR\s\\\"\-AsPlainText\\\"\sOR\s\\\"Net\.NetworkCredential\\\".{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string19 = /.{0,1000}\\GraphRunner\.ps1.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string20 = /.{0,1000}\\GraphRunner\-main.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string21 = /.{0,1000}\\interesting\-teamsmessages\.csv.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string22 = /.{0,1000}\\Passwords\.docx.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string23 = /.{0,1000}\]\sListing\sGraphRunner\smodules\?.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string24 = /.{0,1000}\-\-\-All\sAzure\sAD\sUser\sPrincipal\sNames\-\-\-.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string25 = /.{0,1000}Beau\sBullock\s\(\@dafthack\).{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string26 = /.{0,1000}dafthack\/GraphRunner.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string27 = /.{0,1000}deckard\@tyrellcorporation\.io.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string28 = /.{0,1000}DON\'T\sRUN\sTHIS\sIN\sYOUR\sWEB\sROOT\sAS\sIT\sWILL\sOUTPUT\sACCESS\sTOKENS.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string29 = /.{0,1000}filetype:credentials.{0,1000}\sAND\s\(\(client_id\sOR\sclientID\)\sAND\s\(tenant\)\sAND\s\(secret\)\).{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string30 = /.{0,1000}filetype:credentials.{0,1000}\sAND\s\(\\\"AWS_ACCESS_KEY_ID\\\"\sOR\s\\\"AWS_SECRET_ACCESS_KEY\\\".{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string31 = /.{0,1000}filetype:credentials.{0,1000}\sAND\s\(begin\sNEAR\(n\=1\)\s\(RSA\sOR\sOPENSSH\sOR\sDSA\sOR\sEC\sOR\sPGP\)\sNEAR\(n\=1\)\sKEY\).{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string32 = /.{0,1000}filetype:pem.{0,1000}AND\s\(\\\"BEGIN\sRSA\sPRIVATE\sKEY\\\"\sOR\s\\\"BEGIN\sDSA\sPRIVATE\sKEY\\\"\sOR\s\\\"BEGIN\sEC\sPRIVATE\sKEY\\.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string33 = /.{0,1000}Get\-AzureADUsers\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string34 = /.{0,1000}Get\-GraphTokens.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string35 = /.{0,1000}Get\-SharePointSiteURLs.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string36 = /.{0,1000}Get\-TeamsChat\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string37 = /.{0,1000}Get\-TeamsChat.{0,1000}Downloads\sfull\sTeams\schat\sconversations.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string38 = /.{0,1000}GraphRunner.{0,1000}access_tokens\.txt.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string39 = /.{0,1000}GraphRunner.{0,1000}chatsResponse\.json.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string40 = /.{0,1000}GraphRunner\/PHPRedirector.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string41 = /.{0,1000}GraphRunner\\PHPRedirector.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string42 = /.{0,1000}GraphRunnerGUI\.html.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string43 = /.{0,1000}Guest\sUser\sPolicy:\sGuest\susers\shave\sthe\ssame\saccess\sas\smembers\s\(most\sinclusive\).{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string44 = /.{0,1000}http:\/\/localhost:8000\/emailviewer\.html.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string45 = /.{0,1000}https:\/\/YOURREDIRECTWEBSERVER\.azurewebsites\.net.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string46 = /.{0,1000}iamlordvoldemort\@31337schoolofhackingandwizardry\.com.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string47 = /.{0,1000}Invoke\-AutoOAuthFlow.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string48 = /.{0,1000}Invoke\-AutoTokenRefresh.{0,1000}access_token\.txt.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string49 = /.{0,1000}Invoke\-BruteClientIDAccess.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string50 = /.{0,1000}Invoke\-CheckAccess.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string51 = /.{0,1000}Invoke\-DeleteGroup\s\-Tokens\s.{0,1000}\s\-groupID\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string52 = /.{0,1000}Invoke\-DeleteOAuthApp\s\-Tokens\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string53 = /.{0,1000}Invoke\-DeleteOAuthApp.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string54 = /.{0,1000}Invoke\-DriveFileDownload.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string55 = /.{0,1000}Invoke\-DriveFileDownload.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string56 = /.{0,1000}Invoke\-DumpApps.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string57 = /.{0,1000}Invoke\-DumpCAPS.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string58 = /.{0,1000}Invoke\-ForgeUserAgent\s\-Device\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string59 = /.{0,1000}Invoke\-GraphOpenInboxFinder\s\-Tokens.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string60 = /.{0,1000}Invoke\-GraphOpenInboxFinder.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string61 = /.{0,1000}Invoke\-GraphRecon.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string62 = /.{0,1000}Invoke\-GraphRunner.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string63 = /.{0,1000}Invoke\-HTTPServer.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string64 = /.{0,1000}Invoke\-ImmersiveFileReader.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string65 = /.{0,1000}Invoke\-InjectOAuthApp\s\-AppName\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string66 = /.{0,1000}Invoke\-InjectOAuthApp.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string67 = /.{0,1000}Invoke\-InviteGuest.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string68 = /.{0,1000}Invoke\-RefreshAzureAppTokens\s\-ClientId\s.{0,1000}\s\-ClientSecret\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string69 = /.{0,1000}Invoke\-RefreshGraphTokens.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string70 = /.{0,1000}Invoke\-RefreshToSharePointToken.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string71 = /.{0,1000}Invoke\-SearchMailbox.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string72 = /.{0,1000}Invoke\-SearchSharePointAndOneDrive.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string73 = /.{0,1000}Invoke\-SearchTeams\s\-Tokens\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string74 = /.{0,1000}Invoke\-SearchUserAttributes.{0,1000}Search\sfor\sterms\sacross\sall\suser\sattributes\sin\sa\sdirectory.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string75 = /.{0,1000}Invoke\-SecurityGroupCloner\s\-Tokens\s.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string76 = /.{0,1000}Invoke\-SecurityGroupCloner.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string77 = /.{0,1000}Listening\sfor\sincoming\srequests\son\shttp:\/\/localhost:\$port\/.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string78 = /.{0,1000}List\-GraphRunnerModules.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string79 = /.{0,1000}PHPRedirector.{0,1000}AutoOAuthFlow\.py.{0,1000}/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string80 = /.{0,1000}v\-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57\-albMZ.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
