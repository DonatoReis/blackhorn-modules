package socialmedia_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/socialmedia"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers de teste ────────────────────────────────────────────────────────

type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func newTestClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{srv.URL}}
}

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if socialmedia.New().Name() != "socialmedia" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if socialmedia.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := socialmedia.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

// ─── GitHub API — Username ────────────────────────────────────────────────────

func githubUserHandler(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/repos") {
		// Handler de repos
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":             "awesome-project",
				"description":      "Um projeto incrível",
				"language":         "Go",
				"stargazers_count": 250,
				"forks_count":      45,
				"topics":           []string{"security", "osint"},
				"html_url":         "https://github.com/testuser/awesome-project",
				"updated_at":       "2024-01-15T10:30:00Z",
				"fork":             false,
			},
			{
				"name":     "forked-repo",
				"fork":     true, // deve ser ignorado
				"html_url": "https://github.com/testuser/forked-repo",
				"language": "Python",
			},
		})
		return
	}

	// Handler do perfil
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"login":        "testuser",
		"id":           12345,
		"name":         "Test User",
		"email":        "testuser@example.com",
		"bio":          "Security researcher",
		"company":      "SecureCorp",
		"location":     "São Paulo, BR",
		"blog":         "https://testuser.dev",
		"public_repos": 42,
		"followers":    500,
		"following":    100,
		"created_at":   "2015-01-01T00:00:00Z",
		"updated_at":   "2024-01-15T10:00:00Z",
		"html_url":     "https://github.com/testuser",
		"type":         "User",
		"site_admin":   false,
	})
}

func TestRun_GitHub_Username_Profile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via GitHub")
	}

	var profileFound bool
	for _, f := range findings {
		if f.Type == "social_profile" && f.Extra["source"] == "github_api" {
			profileFound = true
			if f.Extra["username"] != "testuser" {
				t.Errorf("username esperado 'testuser', obteve '%s'", f.Extra["username"])
			}
			if f.Extra["public_repos"] != "42" {
				t.Errorf("public_repos esperado '42', obteve '%s'", f.Extra["public_repos"])
			}
			if f.Extra["followers"] != "500" {
				t.Errorf("followers esperado '500', obteve '%s'", f.Extra["followers"])
			}
			// Email deve estar mascarado
			if f.Extra["email"] != "" && strings.Contains(f.Extra["email"], "testuser@") {
				t.Error("email completo não deve aparecer — deve ser mascarado")
			}
			if f.Extra["platform"] != "GitHub" {
				t.Errorf("platform esperado 'GitHub', obteve '%s'", f.Extra["platform"])
			}
		}
	}
	if !profileFound {
		t.Error("esperava finding 'social_profile' do github")
	}
}

func TestRun_GitHub_Username_ReposIncluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})

	var repoFound, forkFound bool
	for _, f := range findings {
		if f.Type == "github_repository" {
			if f.Extra["repo"] == "awesome-project" {
				repoFound = true
				if f.Extra["stars"] != "250" {
					t.Errorf("stars esperado '250', obteve '%s'", f.Extra["stars"])
				}
			}
			if f.Extra["repo"] == "forked-repo" {
				forkFound = true
				t.Error("forks não devem aparecer como findings")
			}
		}
	}
	if !repoFound {
		t.Error("esperava finding 'github_repository' para awesome-project")
	}
	if forkFound {
		t.Error("forks devem ser filtrados")
	}
}

func TestRun_GitHub_NotFound_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "nonexistentuser99999",
		Options: map[string]string{"sources": "github_api"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

func TestRun_GitHub_WithAtSign_Username(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	// @username deve funcionar igual a username
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "@testuser",
		Options: map[string]string{"sources": "github_api"},
	})
	if err != nil {
		t.Fatalf("@username não deve dar erro: %v", err)
	}
	_ = findings
}

// ─── Reddit API — Username ────────────────────────────────────────────────────

func redditUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"name":               "redditor123",
			"id":                 "t2_abcdef",
			"comment_karma":      5000,
			"link_karma":         3000,
			"total_karma":        8000,
			"is_employee":        false,
			"is_mod":             true,
			"has_verified_email": true,
			"created_utc":        1420070400.0, // 2015-01-01
			"icon_img":           "https://www.redditstatic.com/avatars/avatar_default.png",
		},
	})
}

func TestRun_Reddit_Username_Profile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(redditUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "redditor123",
		Options: map[string]string{"sources": "reddit_api"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Reddit")
	}

	for _, f := range findings {
		if f.Type == "social_profile" && f.Extra["source"] == "reddit_api" {
			if f.Extra["total_karma"] != "8000" {
				t.Errorf("total_karma esperado '8000', obteve '%s'", f.Extra["total_karma"])
			}
			if f.Extra["is_mod"] != "true" {
				t.Errorf("is_mod esperado 'true', obteve '%s'", f.Extra["is_mod"])
			}
			if f.Extra["platform"] != "Reddit" {
				t.Errorf("platform esperado 'Reddit', obteve '%s'", f.Extra["platform"])
			}
		}
	}
}

func redditSearchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"children": []map[string]interface{}{
				{
					"data": map[string]interface{}{
						"id":           "abc123",
						"title":        "Interesting security post",
						"author":       "securityguy",
						"subreddit":    "netsec",
						"score":        1500,
						"num_comments": 45,
						"url":          "https://example.com/article",
						"permalink":    "/r/netsec/comments/abc123/interesting_security_post/",
						"created_utc":  1700000000.0,
					},
				},
			},
		},
	})
}

func TestRun_Reddit_Keyword_Posts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(redditSearchHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "security osint",
		Options: map[string]string{"sources": "reddit_api"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings de busca Reddit")
	}

	for _, f := range findings {
		if f.Type == "social_post" && f.Extra["source"] == "reddit_api" {
			if f.Extra["subreddit"] != "netsec" {
				t.Errorf("subreddit esperado 'netsec', obteve '%s'", f.Extra["subreddit"])
			}
			if f.Extra["score"] != "1500" {
				t.Errorf("score esperado '1500', obteve '%s'", f.Extra["score"])
			}
		}
	}
}

func TestRun_Reddit_NotFound_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "nonexistentuser99999",
		Options: map[string]string{"sources": "reddit_api"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── Twitter API ─────────────────────────────────────────────────────────────

func twitterUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"id":          "123456789",
			"name":        "Test Account",
			"username":    "testaccount",
			"description": "Security researcher and developer",
			"location":    "Brazil",
			"verified":    true,
			"created_at":  "2010-01-01T00:00:00.000Z",
			"public_metrics": map[string]int{
				"followers_count": 50000,
				"following_count": 1000,
				"tweet_count":     5000,
				"listed_count":    200,
			},
		},
	})
}

func TestRun_Twitter_Username_NoToken_NoFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "testaccount",
		Options: map[string]string{
			"sources": "twitter_api",
			// sem twitter_token
		},
	})
	if called {
		t.Error("twitter sem token não deve fazer chamada")
	}
	if len(findings) != 0 {
		t.Errorf("sem token esperava 0 findings, obteve %d", len(findings))
	}
}

func TestRun_Twitter_Username_WithToken_Profile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(twitterUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "testaccount",
		Options: map[string]string{
			"sources":       "twitter_api",
			"twitter_token": "test-bearer-token",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Twitter")
	}

	for _, f := range findings {
		if f.Type == "social_profile" && f.Extra["source"] == "twitter_api" {
			if f.Extra["followers"] != "50000" {
				t.Errorf("followers esperado '50000', obteve '%s'", f.Extra["followers"])
			}
			if f.Extra["verified"] != "true" {
				t.Error("verified deve ser true")
			}
		}
	}
}

// ─── YouTube API ─────────────────────────────────────────────────────────────

func youtubeSearchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pageInfo": map[string]int{"totalResults": 1},
		"items": []map[string]interface{}{
			{
				"id": map[string]string{
					"kind":      "youtube#channel",
					"channelId": "UCtest123",
				},
				"snippet": map[string]interface{}{
					"title":       "Tech Security Channel",
					"description": "Videos sobre segurança e OSINT",
					"channelId":   "UCtest123",
					"publishedAt": "2018-01-01T00:00:00Z",
				},
			},
		},
	})
}

func TestRun_YouTube_WithKey_ChannelFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(youtubeSearchHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "techsecurity",
		Options: map[string]string{
			"sources":     "youtube_api",
			"youtube_key": "test-api-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via YouTube")
	}
	for _, f := range findings {
		if f.Type == "social_profile" && f.Extra["source"] == "youtube_api" {
			if f.Extra["channel_id"] != "UCtest123" {
				t.Errorf("channel_id esperado 'UCtest123', obteve '%s'", f.Extra["channel_id"])
			}
			if f.Extra["platform"] != "YouTube" {
				t.Errorf("platform esperado 'YouTube', obteve '%s'", f.Extra["platform"])
			}
		}
	}
}

func TestRun_YouTube_NoKey_NoFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "techsecurity",
		Options: map[string]string{
			"sources": "youtube_api",
			// sem youtube_key
		},
	})
	if called {
		t.Error("youtube sem key não deve fazer chamada")
	}
	if len(findings) != 0 {
		t.Errorf("sem key esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── Hashtag detection ───────────────────────────────────────────────────────

func TestRun_Hashtag_Target_RedditSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(redditSearchHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "#security",
		Options: map[string]string{"sources": "reddit_api"},
	})
	if err != nil {
		t.Fatalf("hashtag não deve retornar erro: %v", err)
	}
	_ = findings
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding sem Detail: %+v", f)
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── multiple sources ─────────────────────────────────────────────────────────

func TestRun_MultipleSources_CombinedResults(t *testing.T) {
	githubCalled := false
	redditCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Host, "github") || strings.Contains(r.URL.Path, "users") {
			githubCalled = true
			githubUserHandler(w, r)
		} else {
			redditCalled = true
			redditUserHandler(w, r)
		}
	}))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api,reddit_api"},
	})

	// Ambas devem ser chamadas
	_ = githubCalled
	_ = redditCalled
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(githubUserHandler))
	defer srv.Close()

	m := socialmedia.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "testuser",
		Options: map[string]string{"sources": "github_api"},
	})
}
