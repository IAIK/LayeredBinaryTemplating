"use strict";

//
// unlock_pp.js
//
// Removes the protected process protection from all processes.
// Can be automatically rescheduled if wanted.
//
// To run enter the following in WinDbg:
//   .scriptrun <path to script>
// If you want to rerun the script when a new process is spawned use:
//   bp ntdll!NtCreateProcess ".scriptrun <path to script>"
//
function invokeScript() {

    // simpler access to debugLog function
    var dbgOutput = host.diagnostics.debugLog;

    // see "dx Debugger" in WinDbg to learn about accessible fields
    var processes = host.currentSession.Processes; 

    for (var process of processes)
    {
        dbgOutput("Unlocking protected processes: " + String(process.Id) + "\n");
        // disable protection
        process.KernelObject.Protection.Level = 0;
        process.KernelObject.Protection.Type = 0;
        process.KernelObject.Protection.Audit = 0;
        process.KernelObject.Protection.Signer = 0;
    }

    // continue if we reached a breakpoint
    //host.namespace.Debugger.Utility.Control.ExecuteCommand("g");
}