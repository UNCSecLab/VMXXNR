@echo off
set vmxxnrpath=%CD%\vmxxnr\Win7Debug\vmxxnr.sys
sc create vmxxnr type= kernel start= demand binPath= "%vmxxnrpath%"

net start vmxxnr
sc query vmxxnr
