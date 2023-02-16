# This is segments of main file "demo-encryptFileUsingCert.ps1". Segments listed are intended for the party
# who is to encrypt a file
#
# step 1:   obtain certificate from the party who is to decypt the file
#

# step 2: Copy and paste below function in where you will call it to encrypt file
#
Function Encrypt-Asymmetric {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Position=0, Mandatory=$true)][AllowEmptyString()][System.String]
        $ClearText,
        [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][ValidateScript({Test-Path $_ -PathType Leaf})][System.String]
        $PublicCertFilePath
    )
        # Encrypts a string with a public key
        $PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PublicCertFilePath)
        $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
        try{$EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,$true)}
        catch{throw "exception from Encrypt-Asymmetric: `r`n $_.categoaryInfo"}
        $EncryptedBase64String = [Convert]::ToBase64String($EncryptedByteArray)
    
        Return $EncryptedBase64String 
    }

#
# Step 3: Demo section - how to prepare and call Encrypt-Asymmetric funcion
#          Encrypt-asymmetric -clearText "clearText" -PublicCertFilePath "Full absolute path and file name to cert"
#       encrypt function can only encrypt limited size each time, so we have to break cleartext file into smaller chunks
# 

write-host "-----------------------------"
write-host " Encrypting ..."
write-host "-----------------------------"
try{new-item "encrypted.txt" -Force -Confirm:$false > $null}
catch {}
$count=0

#region using chunk'ed string as input
<# using chunk'ed string as input
$originaltxt=(get-content .\original.html) -join "`r`n"
$arrString=$originaltxt -split '(.{60})'  # break file into smaller chunks. CSP can only enncrypt 128 bytes at a time
foreach($line in $arrString){
    #write-host "---[$line]---"
    $count+=1
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}
    try{Encrypt-Asymmetric -ClearText $line -PublicCertPath $PublicCertPath  -ErrorAction Stop | add-Content "encrypted.txt"}
    catch{
        write-host "---[$line]---" -ForegroundColor Red
        write-host "line number $count" -ForegroundColor Yellow
        write-host $_.categoryinfo
    }
}
#>
#endregion

#region using byte array and certObj directly as input
# using chunk'ed string as input
#$byteArr = [System.IO.File]::ReadAllBytes("c:\temp\original.html") #PS v5
$byteArr = Get-Content "./original.txt" -asByteStream -raw  #PS v6 above
$PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("absolute path of where you place certificate")
$count =0
for($i=0;($i -lt ([int][math]::ceiling($byteArr.Count/60))); $i++){
    #write-host "---[$line]---"
    $chunk=$byteArr[($i*60)..(($i+1)*60-1)]
    $count +=1
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}
    try{Encrypt-Asymmetric -byteArray $chunk -PublicCert $PublicCert  -ErrorAction Stop | add-Content "encrypted.txt"}
    catch{
        #write-host "---[$line]---" -ForegroundColor Red
        write-host "line number $count" -ForegroundColor Yellow
        write-host $_.categoryinfo
    }
}
#

#endregion using byte array and certObj directly as input