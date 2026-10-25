package main

import (
	"fmt"
	"os"

	"github.com/carsonzuniga/tinyvault/internal/push"
)

func runCheck(args []string) int {
	fatalCode = 2
	if len(args) > 2 {
		usage()
		return 2
	}
	st := openStore(dbPath(), loadMasterKey())
	defer st.Close()
	pu := push.New(st)

	code := 0
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "tinyvault: "+format+"\n", a...)
		code = 2
	}
	projects, onlyEnvs := args[:min(len(args), 1)], args[min(len(args), 1):]
	if len(projects) == 0 {
		var err error
		if projects, err = st.ListProjects(); err != nil {
			fail("%v", err)
		}
	}
	for _, project := range projects {
		envs := onlyEnvs
		if len(envs) == 0 {
			var err error
			if envs, err = st.ListEnvs(project); err != nil {
				fail("%s: %v", project, err)
			}
		}
		for _, env := range envs {
			targets, err := st.ListTargets(project, env)
			if err != nil {
				fail("%s/%s: %v", project, env, err)
			}
			for _, t := range targets {
				name := project + "/" + env + "/" + t.Name
				status, err := pu.Check(project, env, t.Name, "admin")
				if err != nil {
					fail("%s: %v", name, err)
					continue
				}
				fmt.Printf("%s: %s\n", name, status)
				if status != push.InSync && code == 0 {
					code = 1
				}
			}
		}
	}
	return code
}
