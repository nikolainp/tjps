<# 
 .Synopsis
 ������� ��� ������� ���������������� �������

 .Description
  ������� ��� �������������� ������ ���������������� ������� 1� � ����� �������� PSCustomObject.
  ���� ������ � ������� ������������� � ���� ������. �������� ������� ������������ ����� ������.
  ���� Context ������������� � �������� Context � ����� ������, ���� ������ �������� ������������
  ����� ������ ��������� ���������.
  �������� ���������� ������� �� ������� (��, �����, ��������), �� ���� �������, ���� ����� �������,
  pid ��������.
  ��� �� � �������� ������� ����������� �������������� ����: EventTime - ��� [datetime] ������ ����
  �������, FileName - ��� �����, � ������� ���� ������ � �������, FileType - ��� ��������, �������
  ������ ������ � �������, FilePID - PID ����� ��������

  Don't forget execute it before first usage:
    import-module -Name <path_to_module>\tjps

 .Link
	mail to: nickolay.np@gmail.com

 .Parameter TJCatalog
  ���� � �������� ���������������� �������.

 
 .Example
   parseTJ .\TJFolder -onlynew -dontSaveTime -logType rmngr
   
 	����� �������� ������� � ������� �������� �������, ��� ���� ������ �������� ������� �� ����� ��������.

 .Example
   parseTJ .\TJFolder -event CONN -datefrom "08-25-2017 18:00:00" | where { $_.process -eq "rphost" -and $_.{t:ClientID} -gt 0 }

	����� ������� CONN � ������� 25 ������� 2017 18:00 � ������� � ���� process ������� rphost � � ���� t:ClientID ������ ����.

 .Example
   # ��������� ��������������� �������� ��� ������������� ������ ����� ��������� ������
	�� ������ ��������: https://kb.1c.ru/articleView.jsp?id=86
   
	parseTJ sntx -logtype rmngr -event CALL | where { $_.InBytes -gt 0} | Select-Object FileName, CallID, InBytes | Export-Csv -Path "call.csv"
	parseTJ sntx -logtype rphost -event SCALL | where { $_.process -eq "rphost" -and $_.{t:ClientID} -gt 0} | Select-Object FileType, FilePID, FileName, t:ClientID, CallID | Export-Csv -Path "scall.csv"
	parseTJ sntx -logtype rphost -event CONN  | where { $_.process -eq "rphost" -and $_.{t:ClientID}  -gt 0 -and $_.Usr -ne $null } | Select-Object FileType, FilePID, t:ClientID, Usr -Unique | Export-Csv -Path "conn.csv" -Encoding:UTF8

 .Example
   # �������� �������� ����� ������������ �������, 
   	� ������������ �� ���������:
	parseTJ .\TJFolder -logtype rphost -event SCALL | where { $_.Context -ne $null } | foreach { $hs[$_.Context] += $_.duration } -begin { $hs=@{} };
		$hs.GetEnumerator() | sort -Property value -Desc | select -first 5 | fl

	� ������������ �� ��������� ������ ���������:
	parseTJ .\TJFolder -logtype rphost -event TLOCK | where { $_.Context -ne $null} | foreach { $hs[$_.Context[$_.Context.Length - 1]] += $_.duration } -begin { $hs=@{} };
		$hs.GetEnumerator() | sort -Property value -Desc | select -first 5 | fl
#>

function parseTJ
{

	Param 
	(
		[parameter(Mandatory=$true,
			ValueFromPipeLine=$true)]
		[String]	$TJCatalog
		,

		
		[parameter(Mandatory=$false)]
		[switch]	$onlyNew
		,
		[parameter(Mandatory=$false)]
		[ValidateSet("mmc","ragent","rmngr","rphost")] 
		[string]	$LogType
		,
		[parameter(Mandatory=$false)]
		[alias("PID")]
		[int]		$LogPID
		,
		[parameter(Mandatory=$false)]
		[alias("event")]
		[string[]]	$eventType
		,
		[parameter(Mandatory=$false)]
		[datetime]	$DateFrom
		,
		[parameter(Mandatory=$false)]
		[datetime]	$DateTo
		,

		[parameter(Mandatory=$false)]
		[switch]	$dontSaveTime
		,

		[parameter(Mandatory=$false)]
		[switch]	$help
	)



	Begin
	{
		function BeginOfHour ($BufDate)
		{
			$BufDateHour = $null
			if ( $BufDate -ne $null )
			{
				$BufDateHour = $BufDate.AddMinutes($BufDate.Minute * -1)
				$BufDateHour = $BufDateHour.AddSeconds($BufDateHour.Second * -1)
			}
			
			return	$BufDateHour
		}
	
	
		$LastRunHour	= BeginOfHour $global:kb_lastruntime
		$DateFromHour	= BeginOfHour $DateFrom

		
		if ($eventType -ne $null) 
		{
			$eventTypeUpper = @()
			$eventTypeUpperAndComma = @()
			foreach ($line in $eventType)
			{
				$eventTypeUpper	+= $line.ToUpper()
				$eventTypeUpperAndComma	+= [regex](".*," + $line.ToUpper() + ",.*")
			}
		}
		
		$listFilesFinish	= @()
		$totalSize			= 0
		$currentSize		= 0
	}


	Process
	{
		If ($help -eq $true)
		{
			Write-output "��� ������ ���� ������� �������"
			exit;
		}
		
		
		#write-output "Catalog: " $TJCatalog
		$currentSize	= 0
		$old_percent	= 0
		
		$ProgressWatch = [System.Diagnostics.Stopwatch]::StartNew()

		If (Test-Path $TJCatalog)
		{
		
			$listFiles = Get-ChildItem -Path $TJCatalog -Filter  "*.log"  -Recurse | 
				Where-Object {
					($_.PSIsContainer -eq $false) `
					-and	($_.FullName -match ".*" + $LogType + ".*") `
					-and	($_.FullName -match ".*" + $LogPID + ".*")
				}
			
			if ( ($onlyNew -and $global:kb_lastruntime -ne $null) `
				-or $DateFrom -ne $null -or $DateTo -ne $null)
			{
				
				ForEach ($objFile in $listFiles)
				{
					if ($objFile -eq $null) { break; }

					$filename	= $objFile.Name
					$filedate	= [datetime]::parseexact($filename.replace(".log", ""), 'yyMMddHH', $null)
					
					$rc1 = $global:kb_lastruntime -ne $null
					$rc2 =$filedate -ge $LastRunHour

					if ( $onlyNew -and $global:kb_lastruntime -ne $null -and $filedate -ge $LastRunHour)
					{
						$listFilesFinish	+= $objFile
						$totalSize			+= $objFile.Length
					}
					elseif ( $DateFrom -ne $null -or $DateTo -ne $null)
					{
						if ( ($DateFrom -eq $null -or $DateFromHour -le $filedate) `
							-and ($DateTo -eq $null -or $DateTo -gt $filedate) )
						{
							$listFilesFinish	+= $objFile
							$totalSize			+= $objFile.Length
						}
					}
					
					$currentSize	+= 1
					if ( $ProgressWatch.Elapsed.TotalMilliseconds -ge 1000 )
					{
						$percent	= $currentSize * 100 / ($listFiles.Count + 1)
						Write-Progress -Activity "Load:" -status $objFile.FullName -percentComplete $percent
						$ProgressWatch.Reset()
						$ProgressWatch.Start()
					}
				}
				
			}
			else
			{
				ForEach ($objFile in $listFiles)
				{
					$listFilesFinish 	+= $objFile
					$totalSize			+= $objFile.Length
					
					$currentSize		+= 1
					if ( $ProgressWatch.Elapsed.TotalMilliseconds -ge 1000 )
					{
						$percent		= $currentSize * 100 / ($listFiles.Count + 1)
						Write-Progress -Activity "Load:" -status $objFile.FullName -percentComplete $percent
						$ProgressWatch.Reset()
						$ProgressWatch.Start()
					}

				}
			}

			$listFiles = $null
		}
		
	}

	End
	{
		function	addField ( [hashtable] $hash, [string] $keyHash, $valueHash)
		{
			# ������ ������ ���� � ������������� ������
			
			if ( $hash.ContainsKey($keyHash) -eq $false )
			{ $hash[$keyHash] = $valueHash }
			else
			{
				$i = 1;
				$keyHashNumber = "{0}-{1}" -f $keyHash, $i
				while ( $hash.ContainsKey($keyHashNumber) -eq $true )
				{
					$i++
					$keyHashNumber = "{0}-{1}" -f $keyHash, $i
				}
				$hash[$keyHashNumber] = $valueHash
			}
			
		}
	
		function	parseEvent ( [string] $strEvent )
		{
			$hash = @{}
		
			$masTokens	= $strEvent.split(",")
			$duration	= $masTokens[0].split("[.-]")
			
			$hash["Moment"]		= $duration[1]
			$hash["Duration"]	= $duration[2] / 1000000
			$hash["Event"]		= $masTokens[1]
			$hash["Level"]		= $masTokens[2]
		
			$rc1 = 0
			$rc2 = 0
			$longStringFlag	= $false
			for ($i = 3; $i -lt $masTokens.Count; $i++)
			{
			
				$rc1 += [regex]::matches($masTokens[$i], "'").Count
				$rc2 += [regex]::matches($masTokens[$i], """").Count

				if (-not ($longStringFlag -eq $true -and $field.Length -gt 100))
				{
					[void]$fieldBefore.Append($masTokens[$i])
				}
				
				if ($rc1 % 2 -eq 0 -and $rc2 % 2 -eq 0)
				{
					if ($fieldBefore.Length -gt 50) {	$field	= $fieldBefore.ToString(0, 50)	}
						else { $field	= $fieldBefore.ToString() }
					$field			= $fieldBefore.ToString(0, $field.IndexOf("="))
					$fieldBefore	= $fieldBefore.Remove(0, $field.Length + 1)
					
					$fieldVal	= $matchReplaceContextBegin.replace($fieldBefore.ToString(), "")
					$fieldVal	= $matchReplaceContextEnd.replace($fieldVal, "")
					
					if ($field -eq "Prm") { 
						if ($fieldVal.Length > 100) {
							$fieldVal = $fieldVal.SubString(0, 100) 
						}
					}
					if ($field -eq "Context") { $fieldVal = $matchSplitContext.split($fieldVal) }
					
					addField $hash $field $fieldVal
					
					$fieldBefore.Length = 0
					$rc1 = 0
					$rc2 = 0

					$longStringFlag	= $false
				}
				else
				{
					[void]$fieldBefore.Append(",")
					
					If ($fieldBefore.ToString(0, 6) -eq "Locks=")
					{
						$longStringFlag = $true
					}
				}
				
			}
		
			return	$hash
		}


		function	line_event ( [System.Text.StringBuilder] $event, [datetime] $eventTime )
		{
			#New-Variable -Name records -Option private

			$Minutes	= $event.ToString(0, 2)
			$Seconds	= $event.ToString(3, 2)
			
			$recordTime	= $eventTime.AddMinutes($Minutes)
			$recordTime	= $recordTime.AddSeconds($Seconds)
			
					
			$eventForRead = $false
			if ( $onlyNew -and $global:kb_lastruntime -ne $null -and $recordTime -ge $global:kb_lastruntime)
			{
				$eventForRead = $true
			}
			elseif ( $DateFrom -ne $null -or $DateTo -ne $null)
			{
				if ( ($DateFrom -eq $null -or $DateFrom -le $recordTime) `
					-and ($DateTo -eq $null -or $DateTo -ge $recordTime) )
				{
					$eventForRead = $true
				}
			}
			elseif ( ( $onlyNew -eq $false -or ( $onlyNew -and $global:kb_lastruntime -eq $null ) ) `
				-and $DateFrom -eq $null -and $DateTo -eq $null	)
			{
				$eventForRead = $true
			}

			if ($eventForRead -eq $true)
			{
				$records = parseEvent $event
				#write-output $records
				#$records.getType()
				#read-host "��� ������ ������� ����� �������"
				
				$records["EventTime"]	= $recordTime
				$records["FileName"]	= $fileName
				$records["FileType"]	= $fileType
				$records["FilePID"]		= $filePID
				
				# post-check event type
				if ($eventTypeUpper -ne $null)
				{
					$eventType = $records["Event"].Toupper()
					$eventTypeFlag = $false
					foreach ($eventTypeLine in $eventTypeUpper)
					{
						if ($eventType -eq $eventTypeLine)
						{
							$eventTypeFlag = $true
							break
						}
					}
					
					if ($eventTypeFlag -eq $false) { return }
				}
				
				Write-Output (New-Object PSObject -Prop $records)
			}

		}

		function  	check_line_event ([System.Text.StringBuilder] $event, [datetime] $eventTime)
		{
			if ($event.Length -gt 0)
			{
				if ($eventType -ne $null)
				{
					if ($event.Length -gt 62) { $eventLength = 50 }
						else	{	$eventLength = $event.Length - 12	}
					foreach ($eventTypeLine in $eventTypeUpperAndComma)
					{
						if ($eventTypeLine.IsMatch($event.ToString(12, $eventLength)))
						{
							line_event $event $eventTime
							break
						}
					}
				}
				else {
					line_event $event $eventTime
				}
			}
		}


		$currentSize = 0
		$old_percent = 0
		

		[regex]$matchFirstLine	= "\d\d:\d\d\.\d+"
		[regex]$matchReplaceContextBegin	= "^[ '""] *"
		[regex]$matchReplaceContextEnd		= " *[ '""]$"
		[regex]$matchSplitContext			= "[\t]+"
		$lineBefore		= New-Object -TypeName "System.Text.StringBuilder"
		$fieldBefore	= New-Object -TypeName "System.Text.StringBuilder"

		[void]$lineBefore.EnsureCapacity(10 * 1024 * 1024)
		[void]$fieldBefore.EnsureCapacity(10 * 1024 * 1024)

	
		ForEach ($objFile in $listFilesFinish)
		{
			$fileType, $filePID = $objFile.Directory.Name.split("_")
			
			$fileName		= $objFile.Name.replace(".log", "")
			$fileDate		= [datetime]::parseexact($fileName, 'yyMMddHH', $null)
			
			
			$fileIO = [IO.File]::Open($objFile.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
			$fileBS = New-Object System.IO.BufferedStream($FileIO, 12000000)
			$fileSR = New-Object System.IO.StreamReader($FileBS)

			if ($fileSR.Peek() -gt 0)
			{	[void]$lineBefore.Append($fileSR.ReadLine())	}

			while ($fileSR.Peek() -gt 0)
			{
				$line = $fileSR.ReadLine()
				
				if ($line.length -gt 12 `
					-and $matchFirstLine.IsMatch($line.substring(0, 12)) )
				{
					# pre-check event type
					check_line_event $lineBefore $fileDate
					$lineBefore.Length = 0
				}

				[void]$lineBefore.Append($line)

				$currentSize	+= $line.Length - 1
				
				if ( $ProgressWatch.Elapsed.TotalMilliseconds -ge 1000 )
				{
					$percent	= $currentSize * 100 / $totalSize
					if ($percent -gt 100) { $percent = 99 }
					
					$activity_status = "{0} == {1} / {2}" -f $objFile.FullName, $currentSize, $totalSize
					Write-Progress -Activity "Parse:" -status $activity_status  -percentComplete $percent

					$ProgressWatch.Reset()
					$ProgressWatch.Start()
				}
			}

			check_line_event $lineBefore $fileDate
			$lineBefore.Length = 0
			
			$fileSR.Close()
			$fileBS.Close()
			$fileIO.Close()

		}

		#Set time of run
		if ($dontSaveTime -eq $false)
		{
			$global:kb_lastruntime = get-date
		}

		#Write-Verbose ( "Main Loop: {0}" -f $time_MainLoop )
		#Write-Verbose ( "File Open: {0}" -f $time_FileOpen ) 
		#Write-Verbose ( "Progress Show: {0}" -f $time_ProgresShow ) 
		#Write-Verbose ( "Progress Write: {0}" -f $time_ProgressWrite ) 
		#Write-Verbose ( "Line Event: {0}" -f $time_LineEvent ) 
	}

}


<# 
 .Synopsis
  Calculates MD5 hash for property "SQL" event object.

 .Description
  ������� ��������� MD5 �� ���� Sql, ���� ���������� ����� ������� ���������� � ���������� �����.
  ��������� ����� ��������� ������, �������� ���������� � ���� ���������.

  Don't forget execute it before first usage:
    import-module -Name <path_to_module>\kb_tj

 .Link
	mail to: nickolay.np@gmail.com

 .Parameter ObjectEvent
  ������ ������� ��� ����������.

 
 .Example
   parseTJ .\TJFolder -onlynew -dontSaveTime -logType rmngr
   
 	����� �������� ������� � ������� �������� �������, ��� ���� ������ �������� ������� �� ����� ��������.

#>

function sqlToHashMD5
{
	Param 
	(
		[parameter(Mandatory=$true,
			ValueFromPipeLine=$true)]
		[PSObject]	$ObjectEvent
	)


	Begin
	{
		[regex]$matchTempTable	= "#tt[0-9]+"
		[regex]$matchTableName	= "T[0-9]+"

		$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
		$utf8 = new-object -TypeName System.Text.UTF8Encoding
	}


	Process
	{

		if ($ObjectEvent.SQL -ne $null)
		{

			$SQL = $ObjectEvent.$SQL

			$SQL = $matchTempTable.replace($SQL, "#TemplTable")
			$SQL = $SQL.Replace(' ', '')
			#$SQL = $SQL.Replace('execsp_executesqlN''', '')  
			#$SQL = $SQL.Replace([char]10, '')
			#$SQL = $SQL.Replace([char]13, '')

			# remove end of string with parameters
			$parameterIndex = $SQL.IndexOf("p_0")
			if ($parameterIndex -gt 0)	{	$SQL = $SQL.Remove($parameterIndex)	}

			# remove table names
			$SQL = $matchTableName.Replace($SQL, "")
	 
			$SQL = $SQL.Replace('{', '')  
			$SQL = $SQL.Replace('}', '')  
			$SQL = $SQL.Replace('''', '')  
			$SQL = $SQL.Replace('"', '')  
			$SQL = $SQL.Replace('.', '')  
			$SQL = $SQL.Replace(',', '')  
			$SQL = $SQL.Replace(';', '')  
			$SQL = $SQL.Replace(':', '')  
			$SQL = $SQL.Replace('@', '')  
			$SQL = $SQL.Replace('?', '')  
			$SQL = $SQL.Replace('=', '')  
			$SQL = $SQL.ToUpper()  

			#$SQL = $SQL.Substring(0, 4000)  
	 
			#$sqlMD5	= Get-StringHash $SQL "MD5"
			$sqlMD5 = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($SQL)))

			
			if ($ObjectEvent.sqlMD5 -eq $null)
			{	Add-Member -InputObject $ObjectEvent -MemberType NoteProperty -Name "sqlMD5" -Value $sqlMD5	}
			else 
			{	$ObjectEvent.sqlMD5	= $sqlMD5	}

		}

		Write-Output	$ObjectEvent
		
	}

}


export-modulemember -function parseTJ
export-modulemember -function sqlToHashMD5

