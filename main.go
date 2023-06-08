package main

import (
	"log"
	"os/exec"
	"strings"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func hideConsoleWindow() {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatal("Failed to load kernel32.dll:", err)
	}
	defer syscall.FreeLibrary(kernel32)

	proc, err := syscall.GetProcAddress(kernel32, "GetConsoleWindow")
	if err != nil {
		log.Fatal("Failed to get GetConsoleWindow address:", err)
	}

	getConsoleWindow := syscall.NewCallback(proc)
	consoleWindow, _, _ := syscall.Syscall(uintptr(getConsoleWindow), 0, 0, 0, 0)

	user32, err := syscall.LoadLibrary("user32.dll")
	if err != nil {
		log.Fatal("Failed to load user32.dll:", err)
	}
	defer syscall.FreeLibrary(user32)

	proc, err = syscall.GetProcAddress(user32, "ShowWindow")
	if err != nil {
		log.Fatal("Failed to get ShowWindow address:", err)
	}

	showWindow := syscall.NewCallback(proc)
	syscall.Syscall(uintptr(showWindow), 2, consoleWindow, uintptr(0), 0)
}

type Process struct {
	Name string
	Path string
	Icon fyne.Resource
}

func getRunningProcesses() ([]Process, error) {
	var processes []Process

	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, `","`)
		if len(fields) < 2 {
			continue
		}

		name := strings.Trim(fields[0], `"`)
		path := strings.Trim(fields[1], `"`)

		if err != nil {
			log.Printf("Failed to retrieve icon for process '%s': %v", name, err)
		}

		process := Process{
			Name: name,
			Path: path,
		}

		processes = append(processes, process)
	}

	return processes, nil
}

func main() {

	myApp := app.New()
	myWindow := myApp.NewWindow("EdgeGuard Process Sentinel BETA")

	processes, err := getRunningProcesses()
	if err != nil {
		log.Fatal("Failed to retrieve processes:", err)
	}

	list := widget.NewList(
		func() int {
			return len(processes)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i widget.ListItemID, item fyne.CanvasObject) {
			process := processes[i]
			label := item.(*widget.Label)
			label.SetText(process.Name)

			if process.Name == "explorer.exe" {
				label.TextStyle = fyne.TextStyle{Bold: true, Italic: false, Monospace: false} // Dark Red
			} else {
				label.TextStyle = fyne.TextStyle{Bold: false, Italic: false, Monospace: false}
			}
		},
	)

	content := container.NewMax(list)

	suspiciousProcesses := getSuspiciousProcesses(processes)
	suspiciousList := widget.NewList(
		func() int {
			return len(suspiciousProcesses)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i widget.ListItemID, item fyne.CanvasObject) {
			process := suspiciousProcesses[i]
			label := item.(*widget.Label)
			label.SetText(process.Name)
		},
	)
	suspiciousList.OnSelected = func(id widget.ListItemID) {
		selectedProcess := suspiciousProcesses[id]
		confirm := dialog.NewConfirm("Kill Process", "Are you sure you want to kill the selected process?", func(confirmed bool) {
			if confirmed {
				err := killProcess(selectedProcess.Name)
				if err != nil {
					log.Printf("Failed to kill process '%s': %v", selectedProcess.Name, err)
				} else {
					suspiciousProcesses = removeProcessFromSlice(suspiciousProcesses, selectedProcess)
					suspiciousList.Refresh()
				}
			}
		}, myWindow)
		confirm.Show()
	}

	tabs := container.NewAppTabs(
		container.NewTabItem("All Processes", content),
		container.NewTabItem("Suspicious Processes", suspiciousList),
	)

	myWindow.SetContent(tabs)
	myWindow.CenterOnScreen()

	myWindow.Resize(fyne.NewSize(800, 600))

	myWindow.ShowAndRun()

}

func getSuspiciousProcesses(processes []Process) []Process {
	var suspiciousProcesses []Process

	for _, process := range processes {
		if process.Name == "vbc.exe" ||
			process.Name == "MSBuild.exe" ||
			process.Name == "RegAsm.exe" ||
			process.Name == "aspnet_regbrowsers.exe" ||
			process.Name == "csc.exe" ||
			process.Name == "cvtres.exe" ||
			process.Name == "InstallUtil.exe" ||
			process.Name == "RegSvcs.exe" ||
			process.Name == "aspnet_regiis.exe" ||
			process.Name == "aspnet_regsql.exe" ||
			process.Name == "aspnet_state.exe" ||
			process.Name == "AppLaunch.exe" ||
			process.Name == "aspnet_compiler.exe" ||
			process.Name == "AddInProcess32.exe" ||
			process.Name == "AddInUtil.exe" ||
			process.Name == "AddInProcess.exe" ||
			process.Name == "CasPol.exe" ||
			process.Name == "jsc.exe" {
			suspiciousProcesses = append(suspiciousProcesses, process)
		}
	}

	return suspiciousProcesses
}

func killProcess(name string) error {
	cmd := exec.Command("taskkill", "/F", "/IM", name)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func removeProcessFromSlice(processes []Process, target Process) []Process {
	var result []Process
	for _, process := range processes {
		if process != target {
			result = append(result, process)
		}
	}
	return result
}
