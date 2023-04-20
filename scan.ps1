# Spør brukeren om subnettet eller IP-adressen som skal skannes
$subnet = Read-Host "Enter the subnet or IP address to scan (in CIDR format, e.g. 10.10.10.0/24):"

# Spør brukeren om portene som skal skannes
$ports = @()
$defaultPort = "443"
while ($true)
{
    $port = Read-Host "Enter a port to scan (default is $defaultPort, press Enter to continue):"
    if ($port -eq "")
    {
        if ($ports.Length -eq 0)
        {
            $ports += $defaultPort
        }
        break
    }
    else
    {
        $ports += $port
    }
}

# Spør brukeren om filnavnet for resultatene
$outputFile = Read-Host "Enter the output file name (default is ssl-certificates.csv):"
if ($outputFile -eq "")
{
    $outputFile = "ssl-certificates.csv"
}

# Funksjon for å sjekke om en port er åpen på en enhet
function Check-Port($ipAddress, $port)
{
    $socket = New-Object Net.Sockets.TcpClient
    $asyncResult = $socket.BeginConnect($ipAddress, $port, $null, $null)
    $waitHandle = $asyncResult.AsyncWaitHandle
    try
    {
        if ($waitHandle.WaitOne(1000, $false))
        {
            $socket.EndConnect($asyncResult) | Out-Null
            return $true
        }
        else
        {
            return $false
        }
    }
    catch
    {
        return $false
    }
    finally
    {
        $socket.Dispose()
        $waitHandle.Dispose()
    }
}

# Funksjon for å hente SSL-sertifikatet fra en enhet
function Get-SSLInfo($ipAddress, $port)
{
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try
    {
        $tcpClient.Connect($ipAddress, $port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { param($sender, $cert, $chain, $sslPolicyErrors) $true })
        $sslStream.AuthenticateAsClient($ipAddress)
        $cert = $sslStream.RemoteCertificate
        if($cert -ne $null)
        {
            $subject = $cert.Subject
            $issuer = $cert.Issuer
            $validFrom = $cert.GetEffectiveDateString()
            $validTo = $cert.GetExpirationDateString()
            return $subject + "," + $issuer + "," + $validFrom + "," + $validTo
        }
    }
    catch
    {
        return $null
    }
    finally
    {
        $tcpClient.Dispose()
    }
}

# Skanne en enkelt IP-adresse
function Scan-IPAddress($ipAddress, $ports)
{
    $results = @()
    foreach ($port in $ports)
    {
        if (Check-Port $ipAddress $port)
        {
            $sslInfo = Get-SSLInfo $ipAddress $port
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $ipAddress
            $result | Add-Member -MemberType NoteProperty -Name "Port" -Value $port
            $result | Add-Member -MemberType NoteProperty -Name "SSL Certificate" -Value $sslInfo
            $results += $result
            }
        }

return $results

}


