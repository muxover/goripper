package modules

import (
	"debug/buildinfo"
	"sort"
	"strings"
)

type ModuleInfo struct {
	MainModule   string
	GoVersion    string
	Dependencies []Dependency
}

type Dependency struct {
	Path          string
	Version       string
	UsedFunctions int
	CVEs          []string
}

func Extract(binaryPath string, funcPackages []string) (*ModuleInfo, error) {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return nil, err
	}

	funcsByModule := make(map[string]int)
	for _, pkg := range funcPackages {
		for _, dep := range info.Deps {
			modPath := dep.Path
			if dep.Replace != nil {
				modPath = dep.Replace.Path
			}
			if pkg == modPath || strings.HasPrefix(pkg, modPath+"/") {
				funcsByModule[modPath]++
				break
			}
		}
	}

	deps := make([]Dependency, 0, len(info.Deps))
	for _, dep := range info.Deps {
		path, version := dep.Path, dep.Version
		if dep.Replace != nil {
			path, version = dep.Replace.Path, dep.Replace.Version
		}
		deps = append(deps, Dependency{
			Path:          path,
			Version:       version,
			UsedFunctions: funcsByModule[path],
			CVEs:          checkCVEs(path, version),
		})
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Path < deps[j].Path })

	return &ModuleInfo{
		MainModule:   info.Main.Path,
		GoVersion:    info.GoVersion,
		Dependencies: deps,
	}, nil
}
