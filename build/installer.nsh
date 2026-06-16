; Custom NSIS hooks for the GreyIQ installer (wired via build.nsis.include).
;
; GreyIQ's local model trains on a bundled native-text extract of the
; Manual_pdfs library. That corpus ships INSIDE the frozen backend resource, so
; it is installed automatically by both the installer and the portable build —
; on first launch the backend copies it into the per-user runtime data folder
; (%APPDATA%\GreyIQ\runtime\data) where the trainer picks it up.
;
; In addition, we drop a discoverable "training-data" folder in the install
; directory so the seed corpus is visible and users can see what GreyIQ learns
; from. Adding more material for training is done from inside the app, which
; writes to the per-user runtime folder above.

!macro customInstall
  CreateDirectory "$INSTDIR\training-data"
  ; The seed corpus is bundled in the backend resources; surface a copy if present.
  ; PyInstaller 6.x (pinned) puts datas under _internal/, so copy the legacy flat
  ; path first (fallback for older toolchains) and the _internal path LAST so the
  ; current layout always wins. /SILENT = a missing source path is non-fatal.
  CopyFiles /SILENT "$INSTDIR\resources\backend\seed\greyiq_manual_pdfs.txt" "$INSTDIR\training-data\greyiq_manual_pdfs.txt"
  CopyFiles /SILENT "$INSTDIR\resources\backend\_internal\seed\greyiq_manual_pdfs.txt" "$INSTDIR\training-data\greyiq_manual_pdfs.txt"
!macroend

!macro customUnInstall
  RMDir /r "$INSTDIR\training-data"
!macroend
