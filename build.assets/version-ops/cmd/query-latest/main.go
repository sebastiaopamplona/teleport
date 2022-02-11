/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command query-latest returns the highest semver release for a versionSpec
// query-latest ignores drafts and pre-releases.
//
// For example:
//  query-latest -version-spec v8.1.5     -> v8.1.5
//  query-latest -version-spec v8.1.3     -> error, no matching release (this is a tag, but not a release)
//  query-latest -version-spec v8.0.0-rc3 -> error, no matching release (this is a pre-release, in github and in semver)
//  query-latest -version-spec v7.0       -> v7.0.2
//  query-latest -version-spec v5         -> v5.2.4
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gravitational/teleport/build.assets/version-ops/lib"
	"github.com/gravitational/trace"
	"golang.org/x/mod/semver"
)

func main() {
	versionSpec, err := parseFlags()
	if err != nil {
		log.Fatalf("Failed to parse flags: %v.", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tag, err := getLatest(ctx, versionSpec, lib.NewGitHub())
	if err != nil {
		log.Fatalf("Query failed: %v.", err)
	}

	fmt.Println(tag)
}

func parseFlags() (string, error) {
	versionSpec := flag.String("version-spec", "", "spec to get the latest release from (e.g. v7 or v8.1")
	flag.Parse()

	if *versionSpec == "" {
		return "", trace.BadParameter("version-spec missing")
	}
	return *versionSpec, nil
}

func getLatest(ctx context.Context, versionSpec string, gh lib.GitHub) (string, error) {
	releases, err := gh.ListReleases(ctx, "gravitational", "teleport")
	if err != nil {
		return "", trace.Wrap(err)
	}
	if len(releases) == 0 {
		return "", trace.BadParameter("failed to find any releases on GitHub")
	}

	// filter drafts and prereleases, which shouldn't be tracked by latest docker images
	tags := make([]string, 0)
	for _, r := range releases {
		if r.GetDraft() {
			continue
		}
		if r.GetPrerelease() {
			continue
		}
		tag := r.GetTagName()
		if semver.Prerelease(tag) != "" {
			continue
		}
		tags = append(tags, tag)
	}

	semver.Sort(tags)

	// semver.Sort is ascending, so we loop in reverse
	for i := len(tags) - 1; i >= 0; i-- {
		tag := tags[i]
		if strings.HasPrefix(tag, versionSpec) {
			return tag, nil
		}
	}

	return "", trace.BadParameter("no releases matched " + versionSpec)
}
