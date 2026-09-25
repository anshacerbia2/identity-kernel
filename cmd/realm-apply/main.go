// Command realm-apply compares the realm definition in realm/ with a live Keycloak and, with
// -apply, converges the realm to it.
//
//	realm-apply -environment development -url https://identity.dev.example            # plan
//	realm-apply -environment development -url https://identity.dev.example -apply     # apply
//
// Credentials come from the environment, never from a flag, so they stay out of shell history:
// KEYCLOAK_ADMIN_CLIENT_ID and KEYCLOAK_ADMIN_CLIENT_SECRET for a master-realm service account, or
// KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD for the bootstrap administrator.
//
// The applied revision is recorded in the realm. The next run reads the definition at that
// revision from git and compares it with the live realm; any difference was made outside this
// tool -- console drift -- and the run refuses to apply over it (exit 2). Revert the change in
// Keycloak, or commit it to realm/ and apply with -adopt.
//
// Exit status: 0 success, 1 error, 2 refused (drift or an unmanaged realm), 3 changes pending
// under -require-in-sync.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

const (
	exitError    = 1
	exitRefused  = 2
	exitPending  = 3
	applyTimeout = 5 * time.Minute
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("realm-apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", os.Getenv("KEYCLOAK_URL"), "Keycloak base URL (default $KEYCLOAK_URL)")
	environmentName := flags.String("environment", "", "target environment: local, ci, or development")
	dir := flags.String("definition", "realm", "directory holding the realm definition")
	apply := flags.Bool("apply", false, "apply the plan; without it the run only reads and reports")
	adopt := flags.Bool("adopt", false, "accept the live realm as the baseline instead of refusing drift")
	requireInSync := flags.Bool("require-in-sync", false, "exit 3 when the plan has changes pending")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "realm-apply: "+format+"\n", a...)
		return exitError
	}

	environment, err := realmdef.ParseEnvironment(*environmentName)
	if err != nil {
		return fail("%v", err)
	}
	client, err := admin.New(*baseURL, nil, admin.Credentials{
		ClientID:     os.Getenv("KEYCLOAK_ADMIN_CLIENT_ID"),
		ClientSecret: os.Getenv("KEYCLOAK_ADMIN_CLIENT_SECRET"),
		Username:     os.Getenv("KEYCLOAK_ADMIN_USER"),
		Password:     os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
	})
	if err != nil {
		return fail("%v", err)
	}
	definition, err := realmdef.Load(*dir)
	if err != nil {
		return fail("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()

	recorded, err := realmdef.ReadRecord(ctx, client, definition.Name())
	if err != nil {
		return fail("reading realm %s: %v", definition.Name(), err)
	}
	var previous *realmdef.Definition
	if recorded.Revision != "" && !*adopt {
		files, err := definitionAt(*dir, recorded.Revision)
		if err != nil {
			return fail("the realm was last applied from revision %s, which this checkout cannot read (%v); "+
				"fetch it, or compare the live realm by hand and pass -adopt", recorded.Revision, err)
		}
		parsed, err := realmdef.Parse(files)
		if err != nil {
			return fail("the definition at the recorded revision %s does not parse: %v", recorded.Revision, err)
		}
		if parsed.Digest() != recorded.Digest {
			return fail("the definition at revision %s does not reproduce what was applied (digest %s, "+
				"recorded %s); it was applied from an uncommitted tree. Compare the live realm by hand and pass "+
				"-adopt", recorded.Revision, parsed.Digest(), recorded.Digest)
		}
		previous = &parsed
	}

	plan, err := realmdef.NewPlan(ctx, client, definition, previous)
	if err != nil {
		return fail("%v", err)
	}
	report(stdout, plan, recorded)

	if len(plan.Drift) > 0 && !*adopt {
		fmt.Fprintf(stderr, "\nrealm-apply: refusing: the live realm carries changes the definition at %s does "+
			"not. Revert them in Keycloak, or commit them to %s and apply with -adopt.\n", recorded.Revision, *dir)
		return exitRefused
	}
	if plan.Unmanaged && !*adopt {
		fmt.Fprintf(stderr, "\nrealm-apply: refusing: realm %s exists and was never applied by this tool, so "+
			"there is no baseline to detect drift against. Review the plan above and pass -adopt to take it over.\n",
			plan.Realm)
		return exitRefused
	}
	if !*apply {
		if *requireInSync && !plan.InSync() {
			return exitPending
		}
		return 0
	}

	revision, err := cleanRevision(*dir)
	if err != nil {
		return fail("%v", err)
	}
	err = realmdef.Apply(ctx, client, plan, realmdef.Options{Environment: environment, Revision: revision, Adopt: *adopt})
	switch {
	case errors.Is(err, realmdef.ErrDrift), errors.Is(err, realmdef.ErrUnmanaged):
		fmt.Fprintf(stderr, "realm-apply: refusing: %v\n", err)
		return exitRefused
	case err != nil:
		return fail("%v", err)
	}
	fmt.Fprintf(stdout, "\napplied revision %s to realm %s; the live realm matches the definition\n", revision, plan.Realm)
	return 0
}

func report(w io.Writer, plan realmdef.Plan, recorded realmdef.Record) {
	switch {
	case !recorded.RealmExists:
		fmt.Fprintf(w, "realm %s does not exist; it will be created\n", plan.Realm)
	case recorded.Revision == "":
		fmt.Fprintf(w, "realm %s exists and carries no applied revision\n", plan.Realm)
	default:
		fmt.Fprintf(w, "realm %s was last applied from revision %s\n", plan.Realm, recorded.Revision)
	}
	fmt.Fprintln(w)
	for _, change := range plan.Changes {
		fmt.Fprintf(w, "  %-9s  %s %s\n", change.Action, change.Kind, change.Name)
		for _, diff := range change.Diffs {
			fmt.Fprintf(w, "               %s\n", diff)
		}
	}
	if len(plan.Drift) > 0 {
		fmt.Fprintf(w, "\nDRIFT -- changed outside this tool since revision %s:\n", recorded.Revision)
		for _, drift := range plan.Drift {
			fmt.Fprintf(w, "  %s\n", drift)
		}
	}
}

// definitionAt reads the definition files as they were at a revision.
func definitionAt(dir, revision string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, name := range realmdef.Files {
		out, err := git(dir, "show", revision+":./"+filepath.ToSlash(name))
		if err != nil {
			return nil, err
		}
		files[name] = out
	}
	return files, nil
}

// cleanRevision is the commit to record, refused when the definition has uncommitted changes: the
// recorded revision would not reproduce what was applied, and the next run could not judge drift.
func cleanRevision(dir string) (string, error) {
	status, err := git(dir, "status", "--porcelain", "--", ".")
	if err != nil {
		return "", fmt.Errorf("reading the definition's git status: %w", err)
	}
	if strings.TrimSpace(string(status)) != "" {
		return "", fmt.Errorf("%s has uncommitted changes; commit them first, so the recorded revision "+
			"reproduces what is applied:\n%s", dir, status)
	}
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("reading the current revision: %w", err)
	}
	return strings.TrimSpace(string(head)), nil
}

func git(dir string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr strings.Builder
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
