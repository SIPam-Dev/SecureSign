@echo off
setlocal

SET "PUBLISHED_BASE=%~dp0"
SET "PATH=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86;%PATH%"

dotnet published\SecureSign.Web.dll

endlocal