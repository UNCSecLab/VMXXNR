del vmxxnr\Win7Debug\vmxxnr.sys
msbuild /t:clean /t:build .\vmxxnr\vmxxnr.vcxproj /p:Configuration="Win7 Debug" /p:Platform=Win32
REM msbuild /t:clean /t:build .\vmxxnr\vmxxnr.vcxproj /p:Configuration="Win7 Debug" /p:Platform=x64