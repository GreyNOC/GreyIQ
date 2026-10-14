; Custom NSIS uninstall hook for old GreyIQ installations. Earlier releases
; created an install-directory training-data folder. Current releases do not.

!macro customUnInstall
  RMDir /r "$INSTDIR\training-data"
!macroend
