// Beispiel-YARA-Regeln fuer Wachturm.
// Alle .yar/.yara-Dateien in diesem Ordner werden beim Start geladen.

rule EICAR_Testdatei
{
    meta:
        beschreibung = "Harmlose Antivirus-Testdatei"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Verdaechtiges_PowerShell_Download
{
    meta:
        beschreibung = "PowerShell laedt Code aus dem Netz und fuehrt ihn aus"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "-EncodedCommand" nocase
    condition:
        $a and ($b or $c) or $d
}

rule Ransomware_Erpressernotiz
{
    meta:
        beschreibung = "Typische Formulierungen aus Erpresser-Nachrichten von Ransomware"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "Ihre Dateien wurden verschluesselt" nocase
        $c = "Ihre Dateien wurden verschlüsselt" nocase
        $d = "bitcoin" nocase
        $e = "decrypt" nocase
        $f = ".onion" nocase
    condition:
        filesize < 200KB and ($a or $b or $c) and 2 of ($d, $e, $f)
}

rule Verdaechtiges_Office_Makro
{
    meta:
        beschreibung = "Office-Makro, das beim Oeffnen Programme startet"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $exec1 = "Shell(" nocase
        $exec2 = "WScript.Shell" nocase
        $exec3 = "powershell" nocase
        $net1 = "URLDownloadToFile" nocase
        $net2 = "MSXML2.XMLHTTP" nocase
    condition:
        any of ($auto*) and any of ($exec*) and any of ($net*)
}

rule Windows_Programm_mit_Script_Dropper
{
    meta:
        beschreibung = "Ausfuehrbare Datei, die Skripte in Autostart-Ordner schreibt"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $start = "\\Start Menu\\Programs\\Startup" nocase wide ascii
        $vbs = ".vbs" nocase wide ascii
        $ps = "-ExecutionPolicy Bypass" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and ($run or $start) and ($vbs or $ps)
}

// Weitere fertige Regelsammlungen:
//   - https://github.com/Yara-Rules/rules
//   - https://github.com/Neo23x0/signature-base
