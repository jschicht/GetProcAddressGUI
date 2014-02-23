#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include <GuiEdit.au3>
#include <WinAPI.au3>
#include <Memory.au3>
#include <Security.au3>
#include <GUIConstantsEx.au3>
#include <WindowsConstants.au3>

$form = GUICreate("Get Address of function - by Joakim Schicht", 430, 245, -1, -1)
$label1 = GUICtrlCreateLabel("Select module (dll):", 20, 10, 100, 17)
$label2 = GUICtrlCreateLabel("Select function:", 20, 50, 100, 20)
$input1 = GUICtrlCreateInput("", 120, 10, 200, 20)
$input2 = GUICtrlCreateInput("", 120, 50, 200, 20)
$button = GUICtrlCreateButton("Retrieve", 190, 85, 75, 25, $ws_group)
$checkOrdinalOrName = GUICtrlCreateCheckbox("Ordinal", 80, 85, 95, 20)
$myctredit = GUICtrlCreateEdit("Output:" & @CRLF, 0, 125, 430, 120, $es_autovscroll + $ws_vscroll)
_guictrledit_setlimittext($myctredit, 512000)
GUISetState(@SW_SHOW)

While 1
	$nmsg = GUIGetMsg()
	Select
		Case $nmsg = $button
			_main()
		Case $nmsg = $gui_event_close
			Exit
	EndSelect
WEnd

Func _main()
	$library = GUICtrlRead($input1)
	$hlibrary = _winapi_loadlibrary($library)
	If GUICtrlRead($checkOrdinalOrName) = 1 Then
		$function = Int(GUICtrlRead($input2))
		$aaddress = DllCall("kernel32.dll", "ptr", "GetProcAddress", "ptr", $hlibrary, "int", $function)
		$lasterror = _winapi_getlasterror()
		If $lasterror <> 0 Then
			_displayinfo("Error: " & _winapi_getlasterrormessage() & @CRLF)
		Else
			_displayinfo("Found function ordinal " & $function & " in module " & $library & " at address: " & $aaddress[0] & @CRLF)
			_displayinfo("Shellcode formatted: " & _genshellcode($aaddress[0]) & @CRLF)
		EndIf
	Else
		$function = GUICtrlRead($input2)
		$aaddress = DllCall("kernel32.dll", "ptr", "GetProcAddress", "ptr", $hlibrary, "str", $function)
		$lasterror = _winapi_getlasterror()
		If $lasterror <> 0 Then
			_displayinfo("Error: " & _winapi_getlasterrormessage() & @CRLF)
		Else
			_displayinfo("Found function " & $function & " in module " & $library & " at address: " & $aaddress[0] & @CRLF)
			_displayinfo("Shellcode formatted: " & _genshellcode($aaddress[0]) & @CRLF)
		EndIf
	EndIf
	_winapi_freelibrary($hlibrary)
	Return
EndFunc

Func _winapi_getprocaddress($hmodule, $sprocess)
	Local $areturn
	$areturn = DllCall("kernel32.dll", "ptr", "GetProcAddress", "ptr", $hmodule, "str", $sprocess)
	If @error Then Return SetError(@error, 0, 0)
	Return SetError(0, 0, $areturn[0])
EndFunc

Func _genshellcode($inp)
	Local $tmp, $out, $mod, $i
	$mod = Hex(Binary($inp))
	$strlen = StringLen($mod)
	For $i = 1 To $strlen Step 2
		$tmp = StringMid($mod, $i, 2)
		$out &= "\x" & $tmp
	Next
	Return $out
EndFunc

Func _displayinfo($verboseinfo)
	GUICtrlSetData($myctredit, $verboseinfo, 1)
EndFunc