; airlock installer hooks (tauri NSIS): after installing, check that Windows
; can run airlock's virtual machines, and offer to turn the Windows
; Hypervisor Platform on (needs administrator, then a restart).
!macro NSIS_HOOK_POSTINSTALL
  ; Left by versions before 0.2: ClamAV's database as ext4 (now squashfs,
  ; written by airlock itself). The 512-byte stub they also left in
  ; clamav\ is dropped by the refresh itself (feeds.rs).
  Delete "$INSTDIR\vm\clamav.ext4"
  IfFileExists "$SYSDIR\WinHvPlatform.dll" airlock_hv_ok 0
    MessageBox MB_YESNO|MB_ICONQUESTION "airlock opens every file in its own virtual machine, which needs the Windows feature $\"Windows Hypervisor Platform$\". It is turned off on this computer.$\r$\n$\r$\nTurn it on now? Windows asks for administrator permission, and the computer must be restarted afterwards." /SD IDNO IDNO airlock_hv_ok
    ExecShellWait "runas" "$SYSDIR\dism.exe" "/online /enable-feature /featurename:HypervisorPlatform /all /norestart" SW_SHOWNORMAL
    MessageBox MB_OK|MB_ICONINFORMATION "Restart your computer to finish turning on Windows Hypervisor Platform. airlock works after the restart." /SD IDOK
  airlock_hv_ok:
!macroend
