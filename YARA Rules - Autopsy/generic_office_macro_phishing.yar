Detects malicious Office macros used for initial access (common across APT35 campaigns and others).

rule Generic_Office_Macro_Phishing
{
    meta:
        description = "Detects suspicious macro behavior in Office documents"
        category = "Initial Access / Macro Malware"

    strings:
        $vba1 = "AutoOpen" nocase
        $vba2 = "Document_Open" nocase
        $vba3 = "Shell" nocase
        $vba4 = "WScript.Shell" nocase
        $vba5 = "powershell" nocase
        $vba6 = "http://" nocase

    condition:
        (2 of ($vba1, $vba2)) and (2 of ($vba3, $vba4, $vba5, $vba6))
}
