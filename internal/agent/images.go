//go:build agent

package agent

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// shortIDLen is the length of the truncated image ID docker prints when
// `--no-trunc` is absent; it is the minimum length accepted for a prefix match
// between two image IDs.
const shortIDLen = 12

// dockerImageEntry mirrors only the fields of a
// `docker images --format '{{json .}}'` line that the report needs. Docker
// emits ONE LINE PER TAG (the same image ID repeats), which is why grouping
// happens in ParseDockerImages.
type dockerImageEntry struct {
	ID         string `json:"ID"`
	Repository string `json:"Repository"`
	Tag        string `json:"Tag"`
	Size       string `json:"Size"`
	CreatedAt  string `json:"CreatedAt"`
}

// dockerDiskUsageEntry mirrors one line of
// `docker system df --format '{{json .}}'` — one line per resource type.
type dockerDiskUsageEntry struct {
	Type        string `json:"Type"`
	Size        string `json:"Size"`
	Reclaimable string `json:"Reclaimable"`
}

// ImagesInfo is the intermediate result of CollectImages: the C6 image
// inventory plus the collection status. It is never serialized on its own —
// DockerInfo.WithImages folds it into the single `docker` report section, which
// carries one ok/error pair for the whole docker CLI surface.
type ImagesInfo struct {
	OK        bool
	Error     string
	Images    []Image
	DiskUsage *DiskUsage
}

// CollectImages gathers the C6 image inventory from
// `docker images --no-trunc --format '{{json .}}'` plus the `docker system df`
// summary, and computes `in_use` by cross-referencing the container inventory
// (which the caller already collected via CollectContainers — the join needs
// container image digests, not a second `docker ps`).
//
// Uses the same injectable Runner seam as docker.go and the same discipline:
// it NEVER returns an error to the caller. Any failure — missing docker CLI,
// permission denied, output docker's next version renamed — folds into
// ImagesInfo{OK:false, Error:…} so the agent's report loop never stops
// reporting the sections that did work.
//
// This is read-only by design: WS-6 is inventory. Image/container control
// actions stay on the SSH path in the backend for this phase.
func CollectImages(run Runner, containers []Container) ImagesInfo {
	if run == nil {
		run = ExecRunner
	}

	// --no-trunc is required, not cosmetic: without it docker prints the
	// 12-char short ID and `docker.images[].id` could not be joined against a
	// container's or a registry's sha256 digest by the backend.
	imagesOut, err := run("docker", "images", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return ImagesInfo{OK: false, Error: "docker images: " + err.Error(), Images: []Image{}}
	}

	images, err := ParseDockerImages(imagesOut)
	if err != nil {
		return ImagesInfo{OK: false, Error: "parse docker images: " + err.Error(), Images: []Image{}}
	}
	markImagesInUse(images, containers)

	info := ImagesInfo{OK: true, Images: images}

	// A broken `docker system df` keeps the image list: the two commands are
	// independent and partial data beats no data (same posture as
	// CollectSystemd's per-unit `show` failures).
	dfOut, err := run("docker", "system", "df", "--format", "{{json .}}")
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "docker system df: "+err.Error())
		return info
	}
	usage, err := ParseDockerSystemDF(dfOut)
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "parse docker system df: "+err.Error())
		return info
	}
	info.DiskUsage = usage
	return info
}

// WithImages folds a C6 image inventory into the container inventory to form
// the single `docker` report section.
//
// A failed image collection never clears the container inventory's OK flag:
// they are independent docker CLI calls, and every pre-C6 consumer of the
// intake reads only `containers`. The failure surfaces in `error` while
// `images`/`disk_usage` are simply omitted from the payload.
func (d DockerInfo) WithImages(img ImagesInfo) DockerInfo {
	d.Images = img.Images
	d.DiskUsage = img.DiskUsage
	if !img.OK && img.Error != "" {
		d.Error = appendErr(d.Error, img.Error)
	}
	return d
}

// ParseDockerImages decodes the line-delimited JSON of
// `docker images --format '{{json .}}'` into the report's Image shape. Lines
// are grouped by image ID and their tags accumulated into RepoTags (docker
// prints one line per tag), preserving first-seen order for a stable report.
// A `<none>` repository/tag is a dangling image: the entry is kept — it is
// exactly what a prune would reclaim — with an empty RepoTags. Malformed JSON
// is an error; a line with no ID is skipped. Exported so tests can feed
// fixtures directly.
func ParseDockerImages(raw []byte) ([]Image, error) {
	images := make([]Image, 0)
	pos := map[string]int{}

	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e dockerImageEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("unmarshal docker images line: %w", err)
		}
		if e.ID == "" {
			continue
		}
		i, seen := pos[e.ID]
		if !seen {
			images = append(images, Image{
				ID:       e.ID,
				RepoTags: []string{},
				Size:     parseHumanSize(e.Size),
				Created:  strings.TrimSpace(e.CreatedAt),
			})
			i = len(images) - 1
			pos[e.ID] = i
		}
		if tag := joinRepoTag(e.Repository, e.Tag); tag != "" {
			images[i].RepoTags = append(images[i].RepoTags, tag)
		}
	}
	return images, nil
}

// joinRepoTag builds a "repo:tag" reference, returning "" when either half is
// docker's `<none>` placeholder (dangling image, or a repo whose tag was
// removed) — a half reference would be worse than no reference for the join.
func joinRepoTag(repo, tag string) string {
	repo = strings.TrimSpace(repo)
	tag = strings.TrimSpace(tag)
	if repo == "" || repo == "<none>" || tag == "" || tag == "<none>" {
		return ""
	}
	return repo + ":" + tag
}

// ParseDockerSystemDF decodes the line-delimited JSON of
// `docker system df --format '{{json .}}'` (one line per resource type:
// Images, Containers, Local Volumes, Build Cache) into DiskUsage. Reclaimable
// is the SUM of the per-type reclaimable columns, since docker prints no grand
// total. Unknown resource types are ignored (forward compatibility with new
// docker rows); output with no recognizable row yields a nil DiskUsage and no
// error, so the report just omits the section. Exported so tests can feed
// fixtures directly.
func ParseDockerSystemDF(raw []byte) (*DiskUsage, error) {
	usage := DiskUsage{}
	found := false

	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e dockerDiskUsageEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("unmarshal docker system df line: %w", err)
		}

		size := parseHumanSize(e.Size)
		switch strings.ToLower(strings.TrimSpace(e.Type)) {
		case "images":
			usage.Images = size
		case "containers":
			usage.Containers = size
		case "local volumes", "volumes":
			usage.Volumes = size
		case "build cache":
			usage.BuildCache = size
		default:
			continue
		}
		usage.Reclaimable += parseHumanSize(e.Reclaimable)
		found = true
	}

	if !found {
		return nil, nil
	}
	return &usage, nil
}

// markImagesInUse sets Image.InUse by cross-referencing the image inventory
// with the container inventory.
//
// The join key is the image DIGEST, not the tag: Container.Image is
// Config.Image from `docker inspect` (docker.go), i.e. the tag the container
// was started with ("lincros/api:v1.4.2"), which a retag or a re-pull of the
// same tag makes ambiguous. Container.ImageID (inspect's top-level `Image`) is
// the config digest and is authoritative.
//
// Fallback for a container that reports no ImageID (older docker, or an
// inspect payload without the field): match its started tag against RepoTags.
// An image no container references stays in_use:false.
func markImagesInUse(images []Image, containers []Container) {
	for i := range images {
		images[i].InUse = false
		for _, c := range containers {
			if c.ImageID != "" {
				if sameImageID(images[i].ID, c.ImageID) {
					images[i].InUse = true
					break
				}
				continue
			}
			if tagInRepoTags(images[i].RepoTags, c.Image) {
				images[i].InUse = true
				break
			}
		}
	}
}

// sameImageID compares two image IDs tolerating the `sha256:` algorithm
// prefix and truncation: docker prints the full digest with --no-trunc and a
// 12-char prefix without it, and the two sides of the join may come from
// different docker versions.
func sameImageID(a, b string) bool {
	a = normalizeImageID(a)
	b = normalizeImageID(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return len(a) >= shortIDLen && strings.HasPrefix(b, a)
}

func normalizeImageID(id string) string {
	id = strings.TrimSpace(id)
	if algo, hex, found := strings.Cut(id, ":"); found && strings.EqualFold(algo, "sha256") {
		id = hex
	}
	return strings.ToLower(id)
}

func tagInRepoTags(repoTags []string, containerImage string) bool {
	want := normalizeTag(containerImage)
	if want == "" {
		return false
	}
	for _, t := range repoTags {
		if normalizeTag(t) == want {
			return true
		}
	}
	return false
}

// normalizeTag makes an implicit ":latest" explicit so a container started as
// "redis" matches the "redis:latest" repo tag. A colon in the registry host
// ("registry.local:5000/app") is not a tag separator, and a digest reference
// ("repo@sha256:…") has no tag to complete.
func normalizeTag(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "@") {
		return ref
	}
	lastSlash := strings.LastIndex(ref, "/")
	if strings.Contains(ref[lastSlash+1:], ":") {
		return ref
	}
	return ref + ":latest"
}

// parseHumanSize converts docker's human-readable sizes ("0B", "12.4kB",
// "1.093GB", plus the binary units some versions print) into bytes, tolerating
// the trailing percentage of `docker system df`'s Reclaimable column
// ("1.093GB (98%)") and the "N/A" placeholder. Unparseable input yields 0
// instead of an error: a size docker formats in a way this agent does not know
// must not void the whole inventory.
func parseHumanSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "N/A") {
		return 0
	}
	if open := strings.IndexByte(s, '('); open >= 0 {
		s = strings.TrimSpace(s[:open])
	}

	end := 0
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	value, err := strconv.ParseFloat(s[:end], 64)
	if err != nil || value < 0 {
		return 0
	}

	var mult float64
	switch strings.ToLower(strings.TrimSpace(s[end:])) {
	case "", "b":
		mult = 1
	case "k", "kb":
		mult = 1e3
	case "m", "mb":
		mult = 1e6
	case "g", "gb":
		mult = 1e9
	case "t", "tb":
		mult = 1e12
	case "p", "pb":
		mult = 1e15
	case "kib":
		mult = 1 << 10
	case "mib":
		mult = 1 << 20
	case "gib":
		mult = 1 << 30
	case "tib":
		mult = 1 << 40
	case "pib":
		mult = 1 << 50
	default:
		return 0
	}
	// Rounded, not truncated: docker's decimal strings ("2.514GB") are not
	// exactly representable in float64 and truncation would report one byte
	// less than the obvious value.
	return uint64(math.Round(value * mult))
}
