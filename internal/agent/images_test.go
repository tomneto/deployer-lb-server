//go:build agent

package agent

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Digests are full config digests as `docker images --no-trunc` prints them.
const (
	fixtureAPIImageID     = "sha256:9b1c0a1f7e5d4c3b2a1908f7e6d5c4b3a29181706f5e4d3c2b1a09f8e7d6c5b4"
	fixtureRedisImageID   = "sha256:5a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b"
	fixtureDanglingImgID  = "sha256:0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"
	fixtureOrphanedImgID  = "sha256:1122334455667788990aabbccddeeff00112233445566778899aabbccddeeff0"
	fixtureUnusedTagImgID = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
)

// fixtureImagesJSON is `docker images --no-trunc --format '{{json .}}'` output:
// one line per TAG (the API image repeats under two tags) and `<none>` escaped
// as <none> exactly as the docker CLI emits it.
const fixtureImagesJSON = `{"Containers":"N/A","CreatedAt":"2026-07-28 09:12:44 -0300 -03","CreatedSince":"9 days ago","Digest":"<none>","ID":"` + fixtureAPIImageID + `","Repository":"lincros/api","SharedSize":"N/A","Size":"142MB","Tag":"v1.4.2","UniqueSize":"N/A","VirtualSize":"142.3MB"}
{"Containers":"N/A","CreatedAt":"2026-07-28 09:12:44 -0300 -03","CreatedSince":"9 days ago","Digest":"<none>","ID":"` + fixtureAPIImageID + `","Repository":"lincros/api","SharedSize":"N/A","Size":"142MB","Tag":"latest","UniqueSize":"N/A","VirtualSize":"142.3MB"}
{"Containers":"N/A","CreatedAt":"2026-06-02 18:03:11 -0300 -03","CreatedSince":"2 months ago","Digest":"<none>","ID":"` + fixtureRedisImageID + `","Repository":"redis","SharedSize":"N/A","Size":"116MB","Tag":"latest","UniqueSize":"N/A","VirtualSize":"116.1MB"}
{"Containers":"N/A","CreatedAt":"2026-05-11 07:41:02 -0300 -03","CreatedSince":"3 months ago","Digest":"<none>","ID":"` + fixtureDanglingImgID + `","Repository":"<none>","SharedSize":"N/A","Size":"512MB","Tag":"<none>","UniqueSize":"N/A","VirtualSize":"512MB"}
`

// fixtureSystemDFJSON is `docker system df --format '{{json .}}'` output: one
// line per resource type, sizes and reclaimable as human-readable strings.
const fixtureSystemDFJSON = `{"Active":"3","Reclaimable":"1.093GB (43%)","Size":"2.514GB","TotalCount":"12","Type":"Images"}
{"Active":"2","Reclaimable":"120.3MB (98%)","Size":"122.5MB","TotalCount":"4","Type":"Containers"}
{"Active":"1","Reclaimable":"0B (0%)","Size":"51.2MB","TotalCount":"1","Type":"Local Volumes"}
{"Active":"0","Reclaimable":"1.5GB","Size":"1.5GB","TotalCount":"7","Type":"Build Cache"}
`

// fixtureRunner serves the two docker calls CollectImages makes and fails the
// test on anything else. It drives the Runner seam from docker.go (NOT
// nginx.FakeRunner, which belongs to the lb build tag).
func fixtureRunner(t *testing.T, imagesOut, dfOut string, imagesErr, dfErr error) Runner {
	t.Helper()
	return func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected binary: %s", name)
		}
		switch {
		case args[0] == "images":
			// --no-trunc is load-bearing: the in_use join needs full digests.
			if !reflect.DeepEqual(args, []string{"images", "--no-trunc", "--format", "{{json .}}"}) {
				t.Fatalf("unexpected docker images args: %v", args)
			}
			return []byte(imagesOut), imagesErr
		case args[0] == "system" && len(args) > 1 && args[1] == "df":
			if !reflect.DeepEqual(args, []string{"system", "df", "--format", "{{json .}}"}) {
				t.Fatalf("unexpected docker system df args: %v", args)
			}
			return []byte(dfOut), dfErr
		default:
			t.Fatalf("unexpected docker subcommand: %v", args)
			return nil, nil
		}
	}
}

func TestParseDockerImages_GroupsTagsByID(t *testing.T) {
	got, err := ParseDockerImages([]byte(fixtureImagesJSON))
	if err != nil {
		t.Fatalf("ParseDockerImages() error = %v", err)
	}

	want := []Image{
		{
			ID:       fixtureAPIImageID,
			RepoTags: []string{"lincros/api:v1.4.2", "lincros/api:latest"},
			Size:     142000000,
			Created:  "2026-07-28 09:12:44 -0300 -03",
		},
		{
			ID:       fixtureRedisImageID,
			RepoTags: []string{"redis:latest"},
			Size:     116000000,
			Created:  "2026-06-02 18:03:11 -0300 -03",
		},
		{
			// Dangling: kept in the inventory with no tags — it is exactly
			// what a prune reclaims.
			ID:       fixtureDanglingImgID,
			RepoTags: []string{},
			Size:     512000000,
			Created:  "2026-05-11 07:41:02 -0300 -03",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseDockerImages() = %#v, want %#v", got, want)
	}
}

func TestParseDockerImages_Malformed(t *testing.T) {
	if _, err := ParseDockerImages([]byte("not json\n")); err == nil {
		t.Fatal("expected error for malformed docker images output, got nil")
	}
}

func TestParseDockerImages_EmptyOutput(t *testing.T) {
	got, err := ParseDockerImages([]byte("\n"))
	if err != nil {
		t.Fatalf("ParseDockerImages() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("expected non-nil empty slice for empty output, got %#v", got)
	}
}

func TestParseDockerSystemDF(t *testing.T) {
	got, err := ParseDockerSystemDF([]byte(fixtureSystemDFJSON))
	if err != nil {
		t.Fatalf("ParseDockerSystemDF() error = %v", err)
	}
	want := &DiskUsage{
		Images:      2514000000,
		Containers:  122500000,
		Volumes:     51200000,
		BuildCache:  1500000000,
		Reclaimable: 1093000000 + 120300000 + 0 + 1500000000,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseDockerSystemDF() = %#v, want %#v", got, want)
	}
}

func TestParseDockerSystemDF_Malformed(t *testing.T) {
	if _, err := ParseDockerSystemDF([]byte("{oops")); err == nil {
		t.Fatal("expected error for malformed docker system df output, got nil")
	}
}

func TestParseDockerSystemDF_UnknownTypesOnly(t *testing.T) {
	got, err := ParseDockerSystemDF([]byte(`{"Type":"Something New","Size":"1GB","Reclaimable":"1GB"}`))
	if err != nil {
		t.Fatalf("ParseDockerSystemDF() error = %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil DiskUsage when no known row is present, got %#v", got)
	}
}

func TestCollectImages_HappyPathAndInUse(t *testing.T) {
	containers := []Container{
		{
			// Digest join: authoritative path.
			ID:      "c1",
			Name:    "api",
			Image:   "lincros/api:v1.4.2",
			ImageID: fixtureAPIImageID,
			State:   "running",
		},
		{
			// No ImageID → fallback join by tag ("redis" ⇒ "redis:latest").
			ID:    "c2",
			Name:  "redis",
			Image: "redis",
			State: "running",
		},
	}

	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, fixtureSystemDFJSON, nil, nil), containers)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if info.Error != "" {
		t.Fatalf("expected empty Error, got %q", info.Error)
	}

	inUse := map[string]bool{}
	for _, img := range info.Images {
		inUse[img.ID] = img.InUse
	}
	want := map[string]bool{
		fixtureAPIImageID:    true,  // matched by ImageID
		fixtureRedisImageID:  true,  // matched by repo_tags fallback
		fixtureDanglingImgID: false, // referenced by no container
	}
	if !reflect.DeepEqual(inUse, want) {
		t.Fatalf("in_use = %v, want %v", inUse, want)
	}

	if info.DiskUsage == nil || info.DiskUsage.Images != 2514000000 {
		t.Fatalf("disk usage not parsed: %#v", info.DiskUsage)
	}
}

func TestCollectImages_InUseIgnoresTagWhenContainerHasImageID(t *testing.T) {
	// The container carries a digest that is no longer in the local cache (the
	// tag was re-pulled). The tag still points at an image, but the container
	// is NOT running it — in_use must stay false for the retagged image.
	containers := []Container{
		{ID: "c1", Name: "api", Image: "lincros/api:v1.4.2", ImageID: fixtureOrphanedImgID},
	}

	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, fixtureSystemDFJSON, nil, nil), containers)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	for _, img := range info.Images {
		if img.InUse {
			t.Fatalf("image %s marked in_use, want false (container digest does not match)", img.ID)
		}
	}
}

func TestCollectImages_InUseTruncatedImageID(t *testing.T) {
	// A docker version that reports the short ID on one side of the join must
	// still match (prefix comparison, sha256: prefix stripped).
	short := strings.TrimPrefix(fixtureRedisImageID, "sha256:")[:12]
	containers := []Container{{ID: "c1", Name: "redis", Image: "redis:latest", ImageID: short}}

	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, fixtureSystemDFJSON, nil, nil), containers)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	for _, img := range info.Images {
		if img.ID == fixtureRedisImageID && !img.InUse {
			t.Fatal("expected redis image in_use=true via truncated ImageID match")
		}
	}
}

func TestCollectImages_NoContainers(t *testing.T) {
	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, fixtureSystemDFJSON, nil, nil), nil)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	for _, img := range info.Images {
		if img.InUse {
			t.Fatalf("image %s marked in_use with no containers at all", img.ID)
		}
	}
}

func TestCollectImages_MalformedImagesOutput(t *testing.T) {
	info := CollectImages(fixtureRunner(t, "this is not json", fixtureSystemDFJSON, nil, nil), nil)
	if info.OK {
		t.Fatal("expected OK=false on malformed docker images output")
	}
	if info.Error == "" {
		t.Fatal("expected a non-empty Error on malformed output")
	}
	if info.Images == nil {
		t.Fatal("expected non-nil empty Images slice on failure")
	}
	if info.DiskUsage != nil {
		t.Fatalf("expected nil DiskUsage on failure, got %#v", info.DiskUsage)
	}
}

func TestCollectImages_MalformedSystemDFKeepsImages(t *testing.T) {
	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, "{broken", nil, nil), nil)
	if info.OK {
		t.Fatal("expected OK=false on malformed docker system df output")
	}
	if len(info.Images) != 3 {
		t.Fatalf("expected the 3 parsed images to survive a df failure, got %d", len(info.Images))
	}
	if info.DiskUsage != nil {
		t.Fatalf("expected nil DiskUsage on failure, got %#v", info.DiskUsage)
	}
}

func TestCollectImages_ImagesCommandFails(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("docker: command not found")
	}
	info := CollectImages(run, nil)
	if info.OK {
		t.Fatal("expected OK=false when docker images fails")
	}
	if !strings.Contains(info.Error, "docker images") {
		t.Fatalf("expected Error to name the failing command, got %q", info.Error)
	}
	if info.Images == nil {
		t.Fatal("expected non-nil empty Images slice on failure")
	}
}

func TestCollectImages_SystemDFCommandFails(t *testing.T) {
	info := CollectImages(fixtureRunner(t, fixtureImagesJSON, "", nil, errors.New("permission denied")), nil)
	if info.OK {
		t.Fatal("expected OK=false when docker system df fails")
	}
	if len(info.Images) != 3 {
		t.Fatalf("expected images to survive a df failure, got %d", len(info.Images))
	}
}

func TestDockerInfoWithImages_FailureKeepsContainersOK(t *testing.T) {
	base := DockerInfo{OK: true, Containers: []Container{{ID: "c1", Name: "api"}}}
	got := base.WithImages(ImagesInfo{OK: false, Error: "docker images: boom", Images: []Image{}})

	if !got.OK {
		t.Fatal("a failed image collection must not clear the container inventory's OK flag")
	}
	if got.Error != "docker images: boom" {
		t.Fatalf("Error = %q, want the image collection error surfaced", got.Error)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("containers lost: %#v", got.Containers)
	}
	if got.DiskUsage != nil {
		t.Fatalf("expected nil DiskUsage, got %#v", got.DiskUsage)
	}
}

// The C6 sections are additive: a report produced without them must serialize
// exactly like a pre-C6 report, so the old intake keeps accepting the payload.
func TestDockerInfoJSON_OmitsC6SectionsWhenAbsent(t *testing.T) {
	raw, err := json.Marshal(DockerInfo{OK: true, Containers: []Container{}})
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}
	if got, want := string(raw), `{"ok":true,"containers":[]}`; got != want {
		t.Fatalf("DockerInfo JSON = %s, want %s", got, want)
	}
}

func TestDockerInfoJSON_IncludesC6Sections(t *testing.T) {
	info := DockerInfo{OK: true, Containers: []Container{}}.WithImages(ImagesInfo{
		OK:        true,
		Images:    []Image{{ID: fixtureRedisImageID, RepoTags: []string{"redis:latest"}, Size: 116000000, Created: "2026-06-02 18:03:11 -0300 -03", InUse: true}},
		DiskUsage: &DiskUsage{Images: 2514000000, Containers: 122500000, Volumes: 51200000, BuildCache: 1500000000, Reclaimable: 2713300000},
	})

	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}
	var decoded struct {
		Images []struct {
			ID       string   `json:"id"`
			RepoTags []string `json:"repo_tags"`
			Size     uint64   `json:"size"`
			Created  string   `json:"created"`
			InUse    bool     `json:"in_use"`
		} `json:"images"`
		DiskUsage struct {
			Images      uint64 `json:"images"`
			Containers  uint64 `json:"containers"`
			Volumes     uint64 `json:"volumes"`
			BuildCache  uint64 `json:"build_cache"`
			Reclaimable uint64 `json:"reclaimable"`
		} `json:"disk_usage"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}
	if len(decoded.Images) != 1 || decoded.Images[0].ID != fixtureRedisImageID || !decoded.Images[0].InUse {
		t.Fatalf("docker.images not serialized as contracted: %s", raw)
	}
	if decoded.DiskUsage.BuildCache != 1500000000 || decoded.DiskUsage.Reclaimable != 2713300000 {
		t.Fatalf("docker.disk_usage not serialized as contracted: %s", raw)
	}
}

func TestSameImageID(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{fixtureRedisImageID, fixtureRedisImageID, true},
		{fixtureRedisImageID, strings.TrimPrefix(fixtureRedisImageID, "sha256:"), true},
		{strings.TrimPrefix(fixtureRedisImageID, "sha256:")[:12], fixtureRedisImageID, true},
		{fixtureRedisImageID, fixtureAPIImageID, false},
		// Too short to be a meaningful prefix — must not match.
		{strings.TrimPrefix(fixtureRedisImageID, "sha256:")[:4], fixtureRedisImageID, false},
		{"", fixtureRedisImageID, false},
		{fixtureRedisImageID, "", false},
	}
	for _, c := range cases {
		if got := sameImageID(c.a, c.b); got != c.want {
			t.Errorf("sameImageID(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestNormalizeTag(t *testing.T) {
	cases := map[string]string{
		"redis":                        "redis:latest",
		"redis:7":                      "redis:7",
		"lincros/api":                  "lincros/api:latest",
		"ghcr.io/tomneto/app-a:latest": "ghcr.io/tomneto/app-a:latest",
		// Registry port is not a tag separator.
		"registry.local:5000/app":            "registry.local:5000/app:latest",
		"registry.local:5000/app:v2":         "registry.local:5000/app:v2",
		"lincros/api@sha256:deadbeefdeadbee": "lincros/api@sha256:deadbeefdeadbee",
		"":                                   "",
	}
	for in, want := range cases {
		if got := normalizeTag(in); got != want {
			t.Errorf("normalizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTagInRepoTags_UnusedTaggedImage(t *testing.T) {
	if tagInRepoTags([]string{"lincros/api:v1.4.2"}, "lincros/api:v1.5.0") {
		t.Fatal("different tags of the same repo must not match")
	}
	if tagInRepoTags(nil, "redis:latest") {
		t.Fatal("empty repo_tags must never match")
	}
	if tagInRepoTags([]string{"redis:latest"}, "") {
		t.Fatal("empty container image must never match")
	}
}

func TestParseHumanSize(t *testing.T) {
	cases := map[string]uint64{
		"0B":               0,
		"512B":             512,
		"12.4kB":           12400,
		"142MB":            142000000,
		"2.514GB":          2514000000,
		"1.5GB":            1500000000,
		"1.093GB (98%)":    1093000000,
		"1KiB":             1024,
		"1MiB":             1048576,
		"N/A":              0,
		"":                 0,
		"  116MB  ":        116000000,
		"nonsense":         0,
		"10ZB":             0,
		"-5MB":             0,
		"1.115GB (1.09GB)": 1115000000,
	}
	for in, want := range cases {
		if got := parseHumanSize(in); got != want {
			t.Errorf("parseHumanSize(%q) = %d, want %d", in, got, want)
		}
	}
}

// The unused-but-tagged image is what prune protection cares about: it must be
// reported with in_use=false even though it has repo tags.
func TestMarkImagesInUse_TaggedButUnused(t *testing.T) {
	images := []Image{
		{ID: fixtureUnusedTagImgID, RepoTags: []string{"lincros/api:v1.3.9"}},
		{ID: fixtureAPIImageID, RepoTags: []string{"lincros/api:v1.4.2"}},
	}
	markImagesInUse(images, []Container{{ID: "c1", Image: "lincros/api:v1.4.2", ImageID: fixtureAPIImageID}})

	if images[0].InUse {
		t.Fatal("expected the older tagged image to be in_use=false")
	}
	if !images[1].InUse {
		t.Fatal("expected the running image to be in_use=true")
	}
}
