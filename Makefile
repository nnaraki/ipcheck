BINARY := ipcheck
PREFIX ?= /usr/local

.PHONY: build install install-go uninstall test clean

# カレントにバイナリを生成（./ipcheck）
build:
	go build -o $(BINARY) .

# $(PREFIX)/bin に配置（既定 /usr/local/bin、PATH に通っている想定）。
# 権限が要る場合は: sudo make install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

# go のやり方で $(go env GOPATH)/bin（既定 ~/go/bin）へインストール
install-go:
	go install .

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

test:
	go test ./...

clean:
	rm -f $(BINARY)
