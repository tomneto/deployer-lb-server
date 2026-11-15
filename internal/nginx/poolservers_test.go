package nginx

import (
	"strings"
	"testing"
)

const backendsConf = `http {
    upstream app_pool {
        server 10.0.0.2:8080 weight=3 max_fails=2;
        server 10.0.0.3:8080;
        keepalive 16;
    }
    upstream solo_pool {
        server 10.0.0.9:80;
    }
    upstream exotico_pool {
        server 10.0.0.4:80 route=abc;
    }
}
`

func TestBackendAddressRejectsInjection(t *testing.T) {
	// O furo principal, e não é a allowlist de parâmetros: o endereço é o
	// campo digitado mais livremente. Sem âncora no fim da regex, tudo que
	// vier depois de um endereço válido passa.
	venenos := []string{
		"10.0.0.1:80; } server { listen 80;",
		"10.0.0.1:80;",
		"10.0.0.1:80 }",
		"10.0.0.1:80 #",
		"'10.0.0.1:80'",
		"",
	}
	for _, addr := range venenos {
		if err := ValidateBackend(BackendSpec{Address: addr}); err == nil {
			t.Fatalf("endereço %q tinha de ser recusado", addr)
		}
	}
}

func TestBackendAddressAcceptsTheRealForms(t *testing.T) {
	bons := []string{
		"10.10.0.2:10000", "backend.internal:8080",
		"[2001:db8::1]:443", "unix:/var/run/app.sock",
	}
	for _, addr := range bons {
		if err := ValidateBackend(BackendSpec{Address: addr}); err != nil {
			t.Fatalf("endereço %q é válido e foi recusado: %v", addr, err)
		}
	}
}

func TestBackendParamValueMustMatchItsShape(t *testing.T) {
	// Nome na lista não basta: `weight=abc` chegaria ao arquivo e o nginx
	// recusaria a config inteira.
	if err := ValidateBackend(BackendSpec{
		Address: "10.0.0.1:80", Params: map[string]string{"weight": "abc"},
	}); err == nil {
		t.Fatal("weight não numérico tinha de ser recusado")
	}
	// O nginx recusa weight=0; aceitar aqui seria empurrar o erro para o reload.
	if err := ValidateBackend(BackendSpec{
		Address: "10.0.0.1:80", Params: map[string]string{"weight": "0"},
	}); err == nil {
		t.Fatal("weight=0 tinha de ser recusado")
	}
	// max_fails=0 é LEGÍTIMO: desliga a checagem passiva.
	if err := ValidateBackend(BackendSpec{
		Address: "10.0.0.1:80", Params: map[string]string{"max_fails": "0"},
	}); err != nil {
		t.Fatalf("max_fails=0 desliga a checagem passiva e é válido: %v", err)
	}
	if err := ValidateBackend(BackendSpec{
		Address: "10.0.0.1:80", Params: map[string]string{"inventado": "1"},
	}); err == nil {
		t.Fatal("parâmetro fora do mapa tinha de ser recusado")
	}
}

func TestAddPoolServerLandsBesideTheOthers(t *testing.T) {
	res, err := AddPoolServer(backendsConf, "app_pool", BackendSpec{
		Address: "10.0.0.4:8080", Params: map[string]string{"weight": "2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Remaining != 3 || res.Serving != 3 {
		t.Fatalf("esperava 3 backends servindo, veio %d/%d", res.Serving, res.Remaining)
	}
	if !contains(res.Config, "        server 10.0.0.4:8080 weight=2;") {
		t.Fatalf("a linha nova não nasceu alinhada:\n%s", res.Config)
	}
	// Entra DEPOIS do último server e ANTES do keepalive: um `server` depois
	// do keepalive é válido e ilegível.
	novo := strings.Index(res.Config, "10.0.0.4:8080")
	keep := strings.Index(res.Config, "keepalive 16;")
	if novo > keep {
		t.Fatalf("a linha caiu depois do keepalive:\n%s", res.Config)
	}
	// E o outro pool não foi tocado.
	if !contains(res.Config, "server 10.0.0.9:80;") {
		t.Fatal("mexeu no pool errado")
	}
}

func TestAddPoolServerRefusesADuplicateAddress(t *testing.T) {
	// O nginx aceita, e passa a mandar o dobro de tráfego para a mesma porta.
	if _, err := AddPoolServer(backendsConf, "app_pool", BackendSpec{
		Address: "10.0.0.3:8080",
	}); err == nil {
		t.Fatal("endereço repetido tinha de ser recusado")
	}
}

func TestRemoveDefaultsToMarkingDownNotDeleting(t *testing.T) {
	// `down` é reversível apagando uma palavra; apagar a linha não tem botão
	// de desfazer.
	res, err := RemovePoolServer(backendsConf, "app_pool", "10.0.0.3:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Config, "server 10.0.0.3:8080 down;") {
		t.Fatalf("esperava a linha marcada down:\n%s", res.Config)
	}
	if res.Remaining != 2 || res.Serving != 1 {
		t.Fatalf("esperava 2 backends e 1 servindo, veio %d e %d",
			res.Remaining, res.Serving)
	}
}

func TestHardRemoveOfTheLastBackendIsRefused(t *testing.T) {
	// Um upstream vazio não passa no nginx -t: o reload falha e tudo é
	// restaurado. Recusar antes é melhor que descobrir no rollback.
	if _, err := RemovePoolServer(backendsConf, "solo_pool", "10.0.0.9:80", true); err == nil {
		t.Fatal("apagar o último backend tinha de ser recusado")
	}
	// E marcar down é permitido: o bloco continua válido.
	if _, err := RemovePoolServer(backendsConf, "solo_pool", "10.0.0.9:80", false); err != nil {
		t.Fatalf("marcar down o último backend é válido: %v", err)
	}
}

func TestRemovingTheLastServingBackendIsReported(t *testing.T) {
	// Marcar down o único que ainda atendia desliga o pool inteiro. É
	// permitido, mas quem pediu precisa saber — não foi isso que ele pediu.
	once, err := RemovePoolServer(backendsConf, "app_pool", "10.0.0.2:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := RemovePoolServer(once.Config, "app_pool", "10.0.0.3:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	if twice.Serving != 0 {
		t.Fatalf("o pool parou de atender e Serving diz %d", twice.Serving)
	}
	if twice.Remaining != 2 {
		t.Fatalf("as linhas continuam lá: esperava 2, veio %d", twice.Remaining)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	once, _ := RemovePoolServer(backendsConf, "app_pool", "10.0.0.3:8080", false)
	twice, err := RemovePoolServer(once.Config, "app_pool", "10.0.0.3:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	if twice.Changed != 0 {
		t.Fatalf("a segunda vez não tinha o que mudar, mudou %d", twice.Changed)
	}
}

func TestSetParamsRefusesToRewriteWhatItCannotExpress(t *testing.T) {
	// A linha é REMONTADA a partir do que o editor conhece, então um
	// `slow_start` seria perdido em silêncio. Perder diretiva calado é pior
	// que não deixar editar.
	if _, err := SetPoolServerParams(backendsConf, "exotico_pool", "10.0.0.4:80",
		map[string]string{"weight": "5"}); err == nil {
		t.Fatal("linha com diretiva desconhecida tinha de ser recusada")
	}
}

func TestSetParamsRewritesOnlyTheTargetLine(t *testing.T) {
	res, err := SetPoolServerParams(backendsConf, "app_pool", "10.0.0.2:8080",
		map[string]string{"weight": "5"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Config, "server 10.0.0.2:8080 weight=5;") {
		t.Fatalf("o peso não foi aplicado:\n%s", res.Config)
	}
	// `max_fails=2` SAIU porque não foi enviado — a tela manda o conjunto
	// inteiro, não um patch.
	if contains(res.Config, "max_fails=2") {
		t.Fatalf("o conjunto enviado é o conjunto final:\n%s", res.Config)
	}
	if !contains(res.Config, "server 10.0.0.3:8080;") {
		t.Fatal("mexeu na linha do vizinho")
	}
}

func TestRenderedParamsAreStableAcrossCalls(t *testing.T) {
	// Sem ordem estável, salvar duas vezes sem mudar nada produz arquivos
	// diferentes e o histórico enche de versões que não mudaram coisa alguma.
	params := map[string]string{"weight": "2", "max_fails": "1", "fail_timeout": "10s"}
	a, err := AddPoolServer(backendsConf, "app_pool", BackendSpec{
		Address: "10.0.0.7:80", Params: params})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := AddPoolServer(backendsConf, "app_pool", BackendSpec{
		Address: "10.0.0.7:80", Params: params})
	if a.Config != b.Config {
		t.Fatal("a mesma entrada produziu saídas diferentes")
	}
}
